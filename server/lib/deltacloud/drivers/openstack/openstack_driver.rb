# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#

# Change Log
# 2014.03.24 TIS inc. : Implement Gateway, FloatingIP, SecurityGroup functions.

require 'openstack'

module Deltacloud
  module Drivers
    module Openstack
      class OpenstackDriver < Deltacloud::BaseDriver

        feature :instances, :user_name
        feature :instances, :authentication_key
        feature :instances, :authentication_password
        feature :instances, :user_files
        feature :instances, :user_data
        feature :images, :user_name
        feature :keys, :import_key
        feature :storage_volumes, :volume_name
        feature :storage_volumes, :volume_description

        define_instance_states do
          start.to( :pending )          .on( :create )
          pending.to( :running )        .automatically
          running.to( :running )        .on( :reboot )
          running.to( :stopping )       .on( :stop )
          stopping.to( :stopped )       .automatically
          stopped.to( :finish )         .automatically
          error.from(:running, :pending, :stopping)
        end

        define_hardware_profile('default')

        def supported_collections(credentials)
          #get the collections as defined by 'capability' and 'respond_to?' blocks
          super_collections = super
          begin
            new_client(credentials, "compute")
          rescue Deltacloud::Exceptions::NotImplemented
            super_collections = super_collections - [Deltacloud::Rabbit::ImagesCollection, Deltacloud::Rabbit::InstancesCollection, Deltacloud::Rabbit::InstanceStatesCollection,Deltacloud::Rabbit::KeysCollection,Deltacloud::Rabbit::RealmsCollection, Deltacloud::Rabbit::HardwareProfilesCollection]
          end
          begin
             new_client(credentials, "object-store")
          rescue Deltacloud::Exceptions::NotImplemented #OpenStack::Exception::NotImplemented...
             super_collections = super_collections - [Deltacloud::Rabbit::BucketsCollection]
          end
          begin
              new_client(credentials, "volume")
          rescue Deltacloud::Exceptions::NotImplemented
              super_collections = super_collections - [Deltacloud::Rabbit::StorageVolumesCollection, Deltacloud::Rabbit::StorageSnapshotsCollection]
          end
          super_collections
        end

        def hardware_profiles(credentials, opts = {})
          os = new_client(credentials)
          results = []
          safely do
            if opts[:id]
              begin
                flavor = os.flavor(opts[:id])
                results << convert_from_flavor(flavor)
              rescue => e
                raise e unless e.message =~ /The resource could not be found/
                results = []
              end
            else
              results = os.flavors.collect do |f|
                convert_from_flavor(f)
              end
            end
            filter_hardware_profiles(results, opts)
          end
        end

        def images(credentials, opts={})
          os = new_client(credentials)
          results = []
          profiles = hardware_profiles(credentials)
          safely do
            if(opts[:id])
              begin
                img = os.get_image(opts[:id])
                results << convert_from_image(img, os.connection.authuser)
              rescue => e
                raise e unless e.message =~ /Image not found/
                results = []
              end
            else
              results = os.list_images.collect do |i|
                convert_from_image(i, os.connection.authuser)
              end
            end
          end
          results.each { |img| img.hardware_profiles = profiles }
          filter_on(results, :owner_id, opts)
        end

        def create_image(credentials, opts)
          os = new_client(credentials)
          safely do
            server = os.get_server(opts[:id])
            image_name = opts[:name] || "#{server.name}_#{Time.now}"
            img = server.create_image(:name=>image_name)
            convert_from_image(img, os.connection.authuser)
          end
        end

        def destroy_image(credentials, image_id)
          os = new_client(credentials)
          begin
            image = os.get_image(image_id)
            image.delete!
          rescue
            raise Deltacloud::Exceptions.exception_from_status(500, "Cannot delete image with id #{image_id}")
          end
        end

        def providers(credentials, opts={})
          os = new_client(credentials, "compute", true)
          providers = []
          os.connection.regions_list.each_pair do |region, services|
            resource_types = services.inject([]){|res, cur| res << cur[:service] if ["compute", "volume", "object-store"].include?(cur[:service]); res }
            next if resource_types.empty? #nothing here deltacloud manages
            providers << convert_provider(region)
          end
          providers
        end

        def realms(credentials, opts={})
          os = new_client(credentials)
          realms = []
          limits = ""
          safely do
            lim = os.limits
              limits << "ABSOLUTE >> Max. Instances: #{lim[:absolute][:maxTotalInstances]} Max. RAM: #{lim[:absolute][:maxTotalRAMSize]}   ||   "
              lim[:rate].each do |rate|
                if rate[:regex] =~ /servers/
                  limits << "SERVERS >> Total: #{rate[:limit].first[:value]}  Remaining: #{rate[:limit].first[:remaining]} Time Unit: per #{rate[:limit].first[:unit]}"
                end
              end
          end
          return [] if opts[:id] and opts[:id] != 'default'
          [ Realm.new( { :id=>'default',
                        :name=>'default',
                        :limit => limits,
                        :state=>'AVAILABLE' })]
        end

        def instances(credentials, opts={})
          os = new_client(credentials)
          insts = attachments = nics = []
          safely do
            if have_quantum?(credentials)
              nics = network_interfaces(credentials)
            end
            if opts[:id]
              begin
                server = os.get_server(opts[:id])
                inst_nics = nics.inject([]){|res, cur| res << cur.id if cur.instance == opts[:id]  ;res}
                insts << convert_from_server(server, os.connection.authuser, get_attachments(opts[:id], os), inst_nics)
              rescue => e
                raise e unless e.message =~ /The resource could not be found/
                insts = []
              end
            else
              insts = os.list_servers_detail.collect do |s|
                inst_nics = nics.inject([]){|res, cur| res << cur.id if cur.instance == s[:id]  ;res}
                convert_from_server(s, os.connection.authuser,get_attachments(s[:id], os), inst_nics)
              end
            end
          end
          insts = filter_on( insts, :state, opts )
          insts
        end

        def have_quantum?(credentials)
          begin
            quantum = new_client(credentials, "network")
          rescue => e
            return nil
          end
          quantum
        end

        def create_instance(credentials, image_id, opts)
          os = new_client( credentials, "compute")
          result = nil
#opts[:personality]: path1='server_path1'. content1='contents1', path2='server_path2', content2='contents2' etc
          params = {}
          params[:personality] = extract_personality(opts)
          params[:name] = (opts[:name] && opts[:name].length>0)? opts[:name] : "server#{Time.now.to_s}"
          params[:imageRef] = image_id
          params[:flavorRef] =  (opts[:hwp_id] && opts[:hwp_id].length>0) ?
                          opts[:hwp_id] : hardware_profiles(credentials).first.id
          if opts[:password] && opts[:password].length > 0
            params[:adminPass]=opts[:password]
          end
          if opts[:keyname] && opts[:keyname].length > 0
            params[:key_name]=opts[:keyname]
          end
          if opts[:user_data] && opts[:user_data].length > 0
            params[:user_data]=opts[:user_data]
          end
          if opts[:subnet_id] && opts[:subnet_id].length > 0
            subnet = subnets(credentials, {:id => opts[:subnet_id]}).first
            params[:networks]=[{"uuid" => subnet.network}] unless subnet.nil?
          end
          the_firewalls = firewalls(credentials, {})
          firewall_names = opts.inject([]){|res, (k,v)| res << the_firewalls.find {|fw| fw.id== v}.name if k =~ /firewalls\d+$/; res}
          params[:security_groups] = firewall_names unless firewall_names.empty?
          safely do
            server = os.create_server(params)
            result = convert_from_server(server, os.connection.authuser, get_attachments(server.id, os))
          end
          result
        end


        def reboot_instance(credentials, instance_id)
          os = new_client(credentials)
          safely do
            server = os.get_server(instance_id)
            server.reboot! # sends a hard reboot (power cycle) - could instead server.reboot("SOFT")
            convert_from_server(server, os.connection.authuser, get_attachments(instance_id, os))
          end
        end

        def destroy_instance(credentials, instance_id)
          os = new_client(credentials)
          server = instance = nil
          safely do
            server = os.get_server(instance_id)
            server.delete!
          end
          begin
            server.populate
            instance = convert_from_server(server, os.connection.authuser)
          rescue OpenStack::Exception::ItemNotFound
            instance = convert_from_server(server, os.connection.authuser)
            instance.state = "STOPPED"
          end
          instance
        end

        alias_method :stop_instance, :destroy_instance

        def buckets(credentials, opts={})
          os = new_client(credentials, "object-store")
          buckets = []
          safely do
            if opts[:id]
              buckets << convert_bucket(os.container(opts[:id]))
            else
              os.containers.each{|bucket_name| buckets << convert_bucket(os.container(bucket_name))}
            end
          end
          buckets
        end

        def create_bucket(credentials, name, opts={})
          os = new_client(credentials, "object-store")
          bucket = nil
          safely do
            bucket = os.create_container(name)
          end
          convert_bucket(bucket)
        end

        def delete_bucket(credentials, name, opts={})
          os = new_client(credentials, "object-store")
          safely do
            os.delete_container(name)
          end
        end

        def blobs(credentials, opts={})
          os = new_client(credentials, "object-store")
          blobs = []
          safely do
            bucket = os.container(opts['bucket'])
            if(opts[:id])
              blobs << convert_blob(bucket.object(opts[:id]), opts['bucket'])
            else
              bucket.objects_detail.each{|blob| blobs << convert_blob(blob, opts['bucket'])}
            end
          end
          blobs
        end

        def blob_data(credentials, bucket, blob, opts={})
          os = new_client(credentials, "object-store")
          safely do
            os.container(bucket).object(blob).data_stream do |chunk|
              yield chunk
            end
          end
        end

        def create_blob(credentials, bucket, blob, data, opts={})
          os = new_client(credentials, "object-store")
          safely do
            if(opts[:segment_manifest]) # finalize a segmented blob upload
              os_blob = os.container(bucket).create_object(blob, {:manifest=>"#{bucket}/#{opts[:segmented_blob_id]}"})
            else
              BlobHelper.rename_metadata_headers(opts, "X-Object-Meta-")
              os_blob = os.container(bucket).create_object(blob, {:content_type=> data[:type], :metadata=>opts}, data[:tempfile])
            end
            convert_blob(os_blob, bucket)
          end
        end

        def delete_blob(credentials, bucket, blob, opts={})
          os = new_client(credentials, "object-store")
          safely do
            os.container(bucket).delete_object(blob)
          end
        end

        def blob_metadata(credentials, opts={})
          os = new_client(credentials, "object-store")
          safely do
            os.container(opts['bucket']).object(opts[:id]).metadata
          end
        end

        def update_blob_metadata(credentials, opts={})
          os = new_client(credentials, "object-store")
          safely do
            BlobHelper.rename_metadata_headers(opts["meta_hash"], "")
            blob = os.container(opts['bucket']).object(opts[:id])
            blob.set_metadata(opts['meta_hash'])
          end
        end

        def init_segmented_blob(credentials, opts={})
          opts[:id]
        end

        def blob_segment_id(request, response)
          #could be in http header OR query string:
          segment_order = BlobHelper.segment_order(request)
          blob_name = request.env["PATH_INFO"].gsub(/(&\w*=\w*)*$/, "").split("/").pop
          "#{blob_name}#{segment_order}"
        end

        #params: {:user,:password,:bucket,:blob,:content_type,:content_length,:metadata}
        #params[:context] holds the request object - for getting to blob segment params
        def blob_stream_connection(params)
          if BlobHelper.segmented_blob_op_type(params[:context]) == "segment"
            params[:blob] = "#{params[:blob]}#{BlobHelper.segment_order(params[:context])}"
          end
          tokens = params[:user].split("+")
          user_name, tenant_name = tokens.first, tokens.last
          #need a client for the auth_token and endpoints
          os = OpenStack::Connection.create(:username => user_name, :api_key => params[:password], :authtenant => tenant_name, :auth_url => api_provider, :service_type => "object-store")
          http = Net::HTTP.new(os.connection.service_host, os.connection.service_port)
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
          path = os.connection.service_path + URI.encode("/#{params[:bucket]}/#{params[:blob]}")
          request = Net::HTTP::Put.new(path)
          request['X-Auth-Token'] = os.connection.authtoken
          request['X-Storage-Token'] = os.connection.authtoken
          request['Connection'] = "Keep-Alive"
          request['Content-Type'] = params[:content_type]
          request['Content-Length'] = params[:content_length]
          request['Expect'] = "100-continue"
          metadata = params[:metadata] || {}
          BlobHelper::rename_metadata_headers(metadata, 'X-Object-Meta-')
          metadata.each{|k,v| request[k] = v}
          return http, request
        end

        def keys(credentials, opts={})
          os = new_client(credentials)
          keys = []
          safely do
            os.keypairs.values.each{|key| keys << convert_key(key)}
          end
          filter_on(keys, :id, opts)
        end

        def create_key(credentials, opts={})
          os = new_client(credentials)
          safely do
            params = (opts[:public_key] and opts[:public_key].length > 0)? {:name=>opts[:key_name], :public_key=> opts[:public_key]} : {:name=>opts[:key_name]}
            convert_key(os.create_keypair(params))
          end
        end

        def destroy_key(credentials, opts={})
          os = new_client(credentials)
          safely do
            os.delete_keypair(opts[:id])
          end
        end

        def storage_volumes(credentials, opts={})
          vs = new_client(credentials, "volume")
          volumes = []
          safely do
            if opts[:id]
              volumes <<  convert_volume(vs.get_volume(opts[:id]))
            else
              vs.volumes.each do |vol|
                volumes << convert_volume(vol)
              end
            end
          end
          volumes
        end

        def create_storage_volume(credentials, opts=nil)
          vs = new_client(credentials, "volume")
          params = {}
          safely do
            params[:size] = opts.delete("capacity") || 1
            params[:display_name] = opts.delete("name") || "Volume#{Time.now}"
            params[:display_description] = opts.delete("description") || params[:display_name]
            params[:availability_zone] = opts.delete("realm_id") unless (opts["realm_id"].nil? || opts["realm_id"].empty?)
            opts.delete("commit")
            opts.delete("snapshot_id") #FIXME AFTER ADDING SNAPSHOTS TO OPENSTACK GEM
            volume = convert_volume(vs.create_volume(opts.merge(params)))
          end
        end

        def destroy_storage_volume(credentials, opts={})
          vs = new_client(credentials, "volume")
          safely do
            vs.delete_volume(opts[:id])
          end
        end

        def attach_storage_volume(credentials, opts={})
          vs = new_client(credentials, "volume")
          cs = new_client(credentials, "compute")
          safely do
            cs.attach_volume(opts[:instance_id], opts[:id], opts[:device])
            volume = convert_volume(vs.get_volume(opts[:id]))
          end
        end

        def detach_storage_volume(credentials, opts={})
          vs = new_client(credentials, "volume")
          cs = new_client(credentials, "compute")
          safely do
            cs.detach_volume(opts[:instance_id], opts[:id])
            volume = convert_volume(vs.get_volume(opts[:id]))
          end
        end

        def storage_snapshots(credentials, opts={})
          vs = new_client(credentials, "volume")
          snapshots = []
          safely do
            if opts[:id]
              snapshots <<  convert_snapshot(vs.get_snapshot(opts[:id]))
            else
              vs.snapshots.each do |snap|
                snapshots << convert_snapshot(snap)
              end
            end
          end
          snapshots
        end

        def create_storage_snapshot(credentials, opts={})
          vs = new_client(credentials, "volume")
          safely do
            name = opts[:name] || "snapshot_#{Time.now.to_i}"
            description = opts[:description] || "snapshot from volume #{opts[:volume_id]}"
            params = {:volume_id => opts[:volume_id], :display_name=>name, :display_description=>description}
            convert_snapshot(vs.create_snapshot(params))
          end
        end

        def destroy_storage_snapshot(credentials, opts={})
          vs = new_client(credentials, "volume")
          safely do
            vs.delete_snapshot(opts[:id])
          end
        end

        def networks(credentials, opts={})
          os = new_client(credentials, "network")
          networks = []
          safely do
            subnets = os.subnets
            if opts[:id]
              begin
                net = os.network(opts[:id])
                addr_blocks = get_address_blocks_for(net.id, subnets)
                networks << convert_network(net, addr_blocks)
              rescue => e
                raise e unless e.message =~ /Network not found/
                networks = []
              end
            else
              os.networks.each do |net|
                addr_blocks = get_address_blocks_for(net.id, subnets)
                networks << convert_network(net, addr_blocks)
              end
            end
          end
          networks = filter_on(networks, :id, opts)
        end

        #require params for openstack: {:name}
        def create_network(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            net = os.create_network(opts[:name] || "net_#{Time.now.to_i}")
            convert_network(net, [])
          end
        end

        def destroy_network(credentials, id)
          os = new_client(credentials, "network")
          safely do
            os.delete_network(id)
          end
        end

        def subnets(credentials, opts={})
          os = new_client(credentials, "network")
          subnets = []
          safely do
            if opts[:id]
              begin
                snet = os.subnet opts[:id]
                subnets << convert_subnet(snet)
              rescue => e
                raise e unless e.message =~ /Subnet not found/
                subnets = []
              end
            else
              os.subnets.each do |subnet|
                subnets << convert_subnet(subnet)
              end
            end
          end
          subnets = filter_on(subnets, :id, opts)
        end

        #required params:  :network_id, cidr_block
        #optional params:  :ip_version, :gateway_ip, :allocation_pools
        def create_subnet(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            convert_subnet(os.create_subnet(opts[:network_id], opts[:address_block]))
          end
        end

        def destroy_subnet(credentials, subnet_id)
          os = new_client(credentials, "network")
          safely do
            os.delete_subnet(subnet_id)
          end
        end

        def network_interfaces(credentials, opts={})
          os = new_client(credentials, "network")
          nics = []
          safely do
            if opts[:id]
              begin
                nic = os.port(opts[:id])
                nics << convert_nic(nic)
              rescue => e
                raise e unless e.message =~ /Port not found/
                nics = []
              end
            else
              os.ports.each do |port|
                nics << convert_nic(port)
              end
            end
          end
          nics = filter_on(nics, :id, opts)
        end

        def create_network_interface(credentials, opts={})
          quantum = new_client(credentials, "network")
          safely do
            #first discover the network for the supplied subnet
            #i.e. opts[:network] is actually a subnet
            snet = quantum.subnet(opts[:network])
            network = snet.network_id
            name = opts[:name] || "nic_#{Time.now.to_i}"
            port = quantum.create_port(network, {"fixed_ips"=>[{"subnet_id"=>opts[:network]}], "device_id"=>opts[:instance], "name"=>name})
            convert_nic(port)
          end
        end

        def destroy_network_interface(credentials, nic_id)
          os = new_client(credentials, "network")
          safely do
            os.delete_port(nic_id)
          end
        end

        def gateways(credentials, opts={})
          os = new_client(credentials, "network")
          routers = []
          safely do
            if opts[:id]
              begin
                response = os.connection.req("GET", "/routers/#{opts[:id]}")
                routers << convert_gateway(JSON.parse(response.body)["router"])
              rescue => e
                raise e unless e.message =~ /Router .* could not be found/
                routers = []
              end
            else
              response = os.connection.req("GET", "/routers")
              routers = JSON.parse(response.body)["routers"].inject([]){|res, current| res << convert_gateway(current); res }
            end
          end
          filter_on(routers, :id, opts)
        end

        def create_gateway(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            request_hash = {"router" => {"name" => opts[:name]}}
            request_body = JSON.generate(request_hash)
            response = os.connection.req("POST", "/routers", {:data => request_body})
            convert_gateway(JSON.parse(response.body)["router"])
          end
        end

        def destroy_gateway(credentials, gateway_id)
          os = new_client(credentials, "network")
          safely do
            os.connection.req("DELETE", "/routers/#{gateway_id}")
          end
        end

        def attach_gateway(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            routers = JSON.parse(os.connection.req("GET", "/routers").body)["routers"]
            external_network_ids = routers.map{|r| r["external_gateway_info"]}.compact.uniq.map{|n| n["network_id"]}
            network_id = external_network_ids.first
            request_body = JSON.generate({"router" => {"external_gateway_info" => {"network_id" => network_id}}})
            response = os.connection.req("PUT", "/routers/#{opts[:id]}", {:data => request_body})
            convert_gateway(JSON.parse(response.body)["router"])
          end
        end

        def detach_gateway(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            request_body = JSON.generate({"router" => {"external_gateway_info" => nil}})
            response = os.connection.req("PUT", "/routers/#{opts[:id]}", {:data => request_body})
            convert_gateway(JSON.parse(response.body)["router"])
          end
        end

        def add_interface_to_gateway(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            request_body = JSON.generate({:subnet_id => opts[:subnet_id]})
            os.connection.req("PUT", "/routers/#{opts[:id]}/add_router_interface", {:data => request_body})
          end
        end

        def remove_interface_from_gateway(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            if opts[:subnet_id]
              subnet_ids = [opts[:subnet_id]]
            else
              interfaces = network_interfaces(credentials).select{|interface| interface.instance == opts[:id]}
              subnet_ids = interfaces.map{|interface| interface.network}
            end
            subnet_ids.each do |subnet_id|
              request_body = JSON.generate({:subnet_id => subnet_id})
              os.connection.req("PUT", "/routers/#{opts[:id]}/remove_router_interface", {:data => request_body})
            end
          end
        end

        def addresses(credentials, opts={})
          os = new_client(credentials, "network")
          addresses = []
          safely do
            if opts[:id]
              begin
                response = os.connection.req("GET", "/floatingips/#{opts[:id]}")
                address = JSON.parse(response.body)["floatingip"]
                addresses << convert_address(JSON.parse(response.body), credentials)
              rescue => e
                raise e unless e.message =~ /Floating IP .* could not be found/
                addresses = []
              end
            else
              response = os.connection.req("GET", "/floatingips")
              addresses = JSON.parse(response.body)["floatingips"].inject([]){|res, current| res << convert_address(current, credentials); res}
            end
          end
          filter_on(addresses, :id, opts)
        end

        def create_address(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            if opts[:network_id]
              network_id = opts[:network_id]
            else
              routers = JSON.parse(os.connection.req("GET", "/routers").body)["routers"]
              external_network_ids = routers.map{|r| r["external_gateway_info"]}.compact.uniq.map{|n| n["network_id"]}
              network_id = external_network_ids.first
            end
            request_hash = {"floatingip" => {"floating_network_id" => network_id}}
            request_hash["floatingip"]["port_id"] = opts[:port_id] if opts[:port_id]
            request_body = JSON.generate(request_hash)
            response = os.connection.req("POST", "/floatingips", {:data => request_body})
            convert_address(JSON.parse(response.body)["floatingip"])
          end
        end

        def destroy_address(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            os.connection.req("DELETE", "/floatingips/#{opts[:id]}")
          end
        end

        def associate_address(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            if opts[:network_interface_id]
              port_id = opts[:network_interface_id]
            else
              instance = self.instances(credentials, {:id => opts[:instance_id]}).first
              port_id = instance.network_interfaces.first
            end
            request_body = JSON.generate({"floatingip" => {"port_id" => port_id}})
            os.connection.req("PUT", "/floatingips/#{opts[:id]}", {:data => request_body})
          end
        end

        def disassociate_address(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            request_body = JSON.generate({"floatingip" => {"port_id" => nil}})
            os.connection.req("PUT", "/floatingips/#{opts[:id]}", {:data => request_body})
          end
        end

        def firewalls(credentials, opts={})
          os = new_client(credentials, "network")
          the_firewalls = []
          response = nil
          safely do
            if opts[:id]
              begin
                response = os.connection.req("GET", "/security-groups/#{opts[:id]}")
                the_firewalls << convert_firewall(JSON.parse(response.body)["security_group"])
              rescue => e
                raise e unless e.message =~ /Security-groups .* could not be found/
                routers = []
              end
            else
              response = os.connection.req("GET", "/security-groups")
              JSON.parse(response.body)["security_groups"].each do |security_group|
                the_firewalls << convert_firewall(security_group)
              end
            end
          end
          the_firewalls
        end

        def create_firewall(credentials, opts={})
          os = new_client(credentials, "network")
          request_body = JSON.generate({:security_group =>
                                        {:name => opts[:name], :description => opts[:description]}})
          the_firewall = nil
          safely do
            response = os.connection.req("POST", "/security-groups", {:data => request_body})
            the_firewall = convert_firewall(JSON.parse(response.body)["security_group"])
          end
          the_firewall
        end

        def delete_firewall(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            os.connection.req("DELETE", "/security-groups/#{opts[:id]}")
          end
        end

        def create_firewall_rule(credentials, opts={})
          os = new_client(credentials, "network")
          groups = []
          opts['groups'].each do |k, v|
            groups << {"group_name" => k, "owner" => v}
          end
          request_bodys = []
          groups.each do |group|
            request_bodys << JSON.generate({:security_group_rule => {
              :protocol => opts[:protocol],
              :port_range_min => opts[:port_from],
              :port_range_max => opts[:port_to],
              :remote_group_id => group,
              :direction => opts[:direction],
              :ethertype => opts[:ethertype],
              :security_group_id => opts[:id],
            }})
          end
          opts[:addresses].each do |address|
            request_bodys << JSON.generate({:security_group_rule => {
              :protocol => opts[:protocol],
              :port_range_min => opts[:port_from],
              :port_range_max => opts[:port_to],
              :remote_ip_prefix => address,
              :direction => opts[:direction],
              :ethertype => opts[:ethertype],
              :security_group_id => opts[:id],
            }})
          end
          safely do
            request_bodys.each do |request_body|
              response = os.connection.req('POST', "/security-group-rules", {:data => request_body})
              convert_firewall_rule(JSON.parse(response.body)["security_group_rule"])
            end
          end
        end

        def delete_firewall_rule(credentials, opts={})
          os = new_client(credentials, "network")
          safely do
            os.connection.req("DELETE", "/security-group-rules/#{opts[:rule_id]}")
          end
        end


private
        #for v2 authentication credentials.name == "username+tenant_name"
        def new_client(credentials, type="compute", ignore_provider=false)
          tokens = credentials.user.split("+")
          if credentials.user.empty?
            raise AuthenticationFailure.new(Exception.new("Error: you must supply the username"))
          end
          if (tokens.size != 2 && api_v2)
            raise ValidationFailure.new(Exception.new("Error: expected \"username+tenantname\" as username, you provided: #{credentials.user}"))
          else
            user_name, tenant_name = tokens.first, tokens.last
          end
          #check if region specified with provider:
          provider = api_provider
          if (provider.include?(";"))
            region = provider.split(";").last
            provider = provider.chomp(";#{region}")
          end
          connection_params = {:username => user_name, :api_key => credentials.password, :authtenant => tenant_name, :auth_url => provider, :service_type => type}
          connection_params.merge!({:region => region}) if region && !ignore_provider # hack needed for 'def providers'
          safely do
            raise ValidationFailure.new(Exception.new("Error: tried to initialise Openstack connection using" +
                    " an unknown service_type: #{type}")) unless ["volume", "compute", "object-store", "network"].include? type
            OpenStack::Connection.create(connection_params)
          end
        end

#NOTE: for the convert_from_foo methods below... openstack-compute
#gives Hash for 'flavors' but OpenStack::Compute::Flavor for 'flavor'
#hence the use of 'send' to deal with both cases and save duplication

        def convert_from_flavor(flavor)
          op = (flavor.class == Hash)? :fetch : :send
          hwp = HardwareProfile.new(flavor.send(op, :id).to_s) do
            architecture 'x86_64'
            memory flavor.send(op, :ram).to_i
            storage flavor.send(op, :disk).to_i
            cpu flavor.send(op, :vcpus).to_i
          end
          hwp.name = flavor.send(op, :name)
          return hwp
        end

        def convert_from_image(image, owner)
          op = (image.class == Hash)? :fetch : :send
          Image.new({
                    :id => image.send(op, :id),
                    :name => image.send(op, :name),
                    :description => image.send(op, :name),
                    :owner_id => owner,
                    :state => image.send(op, :status),
                    :architecture => 'x86_64',
                    :creation_time => image.send(op, :created)
                    })
        end

        def convert_from_server(server, owner, attachments=[], nics=[])
          op = (server.class == Hash)? :fetch : :send
          image = server.send(op, :image)
          flavor = server.send(op, :flavor)
         begin
            password = server.send(op, :adminPass) || ""
            rescue IndexError
              password = ""
          end
          inst_params = {
            :id => server.send(op, :id).to_s,
            :realm_id => "default",
            :owner_id => owner,
            :description => server.send(op, :name),
            :name => server.send(op, :name),
            :state => convert_instance_state(server.send(op, :status).downcase),
            :architecture => 'x86_64',
            :image_id => image[:id] || image["id"],
            :instance_profile => InstanceProfile::new(flavor[:id] || flavor["id"]),
            :public_addresses => convert_server_addresses(server, :public),
            :private_addresses => convert_server_addresses(server, :private),
            :username => 'root',
            :password => password,
            :keyname => server.send(op, :key_name),
            :launch_time => server.send(op, :created),
            :storage_volumes => attachments.inject([]){|res, cur| res << {cur[:volumeId] => cur[:device]} ;res}
          }
          unless nics.empty?
            inst_params.merge!(:network_interfaces=>nics)
          end
          inst = Instance.new(inst_params)
          inst.actions = instance_actions_for(inst.state)
          inst.create_image = 'RUNNING'.eql?(inst.state)
          inst
        end

        def convert_instance_state(openstack_state)
          case openstack_state
            when /.*reboot/
              "PENDING"
            when /.*deleting/
              "STOPPING"
            when /.*deleted/
              "STOPPED"
            when /build.*$/
              "PENDING"
            when /error.*/
              "ERROR"
            when /active/
              "RUNNING"
            else
              "UNKNOWN"
          end
        end

        def convert_server_addresses(server, type)
          op, address_label = (server.class == Hash)? [:fetch, :addr] : [:send, :address]
          addresses = (server.send(op, :addresses)[type] || []).collect do |addr|
            type = (addr.send(op, :version) == 4)? :ipv4 : :ipv6
            InstanceAddress.new(addr.send(op, address_label), {:type=>type} )
          end
        end

        def convert_bucket(bucket)
          Bucket.new({ :id => bucket.name,
                       :name => bucket.name,
                       :size => bucket.count,
                       :blob_list => bucket.objects })
        end

        def convert_blob(blob, bucket_name)
          op, blob_meta = (blob.class == Hash)? [:fetch, {}] : [:send, blob.metadata]
          Blob.new({   :id => blob.send(op, :name),
                       :bucket => bucket_name,
                       :content_length => blob.send(op, :bytes),
                       :content_type => blob.send(op, :content_type),
                       :last_modified => blob.send(op, :last_modified),
                       :user_metadata => blob_meta })
        end

        def convert_key(key)
          Key.new(
            :id => key[:name],
            :fingerprint => key[:fingerprint],
            :credential_type => :key,
            :pem_rsa_key => key[:private_key], # only available once, on create_key
            :state => "AVAILABLE"
          )
        end

        def get_attachments(server_id, client)
          if client.api_extensions[:"os-volumes"]
            attachments = client.list_attachments(server_id)
            attachments[:volumeAttachments] || []
          else
            []
          end
        end

        def convert_volume(vol)
          StorageVolume.new({ :id => vol.id,
                              :name => vol.display_name,
                              :created => vol.created_at,
                              :state => (vol.attachments.inject([]){|res, cur| res << cur if cur.size > 0 ; res}.empty?) ? "AVAILABLE" : "IN-USE",
                              :capacity => vol.size,
                              :instance_id => (vol.attachments.first["server_id"] unless vol.attachments.empty?),
                              :device => (vol.attachments.first["device"] unless vol.attachments.empty?),
                              :realm_id => vol.availability_zone,
                              :description => vol.display_description # openstack volumes have a display_description attr
          })
        end

        def convert_snapshot(snapshot)
          StorageSnapshot.new(
            :id => snapshot.id,
            :name => snapshot.display_name,
            :description => snapshot.display_description || snapshot.display_name,
            :state => snapshot.status,
            :storage_volume_id => snapshot.volume_id,
            :created => snapshot.created_at
          )
        end

        def convert_provider(region)
          Provider.new(
            :id => region,
            :name => region,
            :url => [api_provider.split(';').first, region].join(';')
          )
        end

        def get_address_blocks_for(network_id, subnets)
          return [] if subnets.empty?
          addr_blocks = []
          subnets.each do |sn|
            if sn.network_id == network_id
              addr_blocks << sn.cidr
            end
          end
          addr_blocks
        end

        def convert_network(net, addr_blocks)
          Network.new({ :id => net.id,
                        :name => net.name,
                        :subnets => net.subnets,
                        :state => (net.admin_state_up ? "UP" : "DOWN"),
                        :address_blocks => addr_blocks
          })
        end

        def convert_subnet(subnet)
          Subnet.new({  :id => subnet.id,
                        :name => subnet.name,
                        :network => subnet.network_id,
                        :address_block => subnet.cidr,
                        :state => "UP"
          })
        end

        def convert_nic(port)
          NetworkInterface.new({  :id => port.id,
                      :name => port.name,
                      :instance => port.device_id,
                      :network => port.fixed_ips.first["subnet_id"], #subnet, not network for OS
                      :state => (port.admin_state_up ? "UP" : "DOWN" ), # true/false
                      :ip_address =>port.fixed_ips.first["ip_address"]
                      # this is a structure; [{"subnet_id": ID, "ip_address": addr}] - COULD BE >1 address here...
          })
        end

        def convert_gateway(router)
          external_network_id = router["external_gateway_info"].nil? ? nil : router["external_gateway_info"]["network_id"]
          Gateway.new({
            :id => router["id"],
            :name => router["name"],
            :network_id => external_network_id,
            :state => router["status"]
          })
        end

        def convert_address(address, credentials=nil)
          Address.new({ :id => address["id"],
                        :ip_address => address["floating_ip_address"],
                        :instance_id => address["port_id"] # set port_id instead of instance_id
          })
        end

        def convert_firewall(security_group)
          rules = []
          security_group["security_group_rules"].each do |perm|
            rules << convert_firewall_rule(perm)
          end
          Firewall.new(  {  :id => security_group['id'],
                            :name => security_group['name'],
                            :description => security_group['description'],
                            :owner_id => security_group['tenant_id'],
                            :rules => rules
                      }  )
        end

        def convert_firewall_rule(perm)
          sources = []
          unless perm["remote_group_id"].nil?
            sources << {:type => "group",
                        :name => perm["remote_group_id"],
                        :owner => perm["tenant_id"]}
          end
          unless perm["remote_ip_prefix"].nil?
            sources << {:type => "address", :family=>perm["ethertype"],
                        :address=>perm["remote_ip_prefix"].split("/").first,
                        :prefix=>perm["remote_ip_prefix"].split("/").last}
          end
          if perm["remote_group_id"].nil? && perm["remote_ip_prefix"].nil?
            if perm["ethertype"] == "IPv4"
              sources << {:type => "address", :family=>perm["ethertype"],
                          :address=>"0.0.0.0", :prefix=>"0"}
            elsif perm["ethertype"] == "IPv6"
              sources << {:type => "address", :family=>perm["ethertype"],
                          :address=>"::", :prefix=>"0"}
            end 
          end
          if perm["protocol"].nil?
            protocol = 'all'
          else
            protocol = perm["protocol"]
          end
          FirewallRule.new({:id => perm["id"],
                                     :allow_protocol => protocol,
                                     :port_from => perm["port_range_min"],
                                     :port_to => perm["port_range_max"],
                                     :direction => perm["direction"],
                                     :sources => sources})
        end

        #IN: path1='server_path1'. content1='contents1', path2='server_path2', content2='contents2' etc
        #OUT:{local_path=>server_path, local_path1=>server_path2 etc}
        def extract_personality(opts)
          personality_hash =  opts.inject({}) do |result, (opt_k,opt_v)|
            if (opt_k.to_s =~ /^path([1-5]+)/ and opts[opt_k] != nil and opts[opt_k].length > 0)
              unless opts[:"content#{$1}"].nil?
                case opts[:"content#{$1}"]
                  when String
                    tempfile = Tempfile.new("os_personality_local_#{$1}")
                    tempfile.write(opts[:"content#{$1}"])
                    result[tempfile.path]=opts[:"path#{$1}"]
                  when Hash
                    result[opts[:"content#{$1}"][:tempfile].path]=opts[:"path#{$1}"]
                end
              end
            end
            result
          end
        end

        def api_v2
          if api_provider =~ /.*v2.0/
            true
          else
            false
          end
        end

        exceptions do

          on /(Exception::BadRequest|PersonalityFilePathTooLong|PersonalityFileTooLarge|TooManyPersonalityItems)/ do
            status 400
          end

          on /Must supply a :username/ do
            status 401
          end

          on /No API endpoint for region/ do
            status 501
          end

          on /OpenStack::Exception::Authentication/ do
            status 401
          end

          on /OpenStack::Exception::ItemNotFound/ do
            status 404
          end

          on /Exception::Other/ do
            status 500
          end

          on /OpenStack::Exception::NotImplemented/ do
            status 501
          end

        end


      end
    end
  end
end
