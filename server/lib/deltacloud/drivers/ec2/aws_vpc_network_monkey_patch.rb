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

# Change Log
# 2014.03.24 TIS inc. : Implement Gateway function.
#                       Fix return value name to groupId in create_firewall method.
#                       Modify specify device path in attach_volume.
#                       Add VPC id parameter in create_security_group.
#                       Add egress option in QEc2IpPermissionType, QEc2DescribeSecurityGroupsParser, manage_security_group_ingress, describe_security_groups, manage_security_group_egress

unless Aws::Ec2::method_defined?(:create_internet_gateway)
  class Aws::Ec2
    @@api = "2012-07-20"

    # Gateway APIs
    def create_internet_gateway
      link = generate_request("CreateInternetGateway")
      request_info(link, QEc2CreateInternetGatewayParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def describe_internet_gateways(list=[])
      link = generate_request("DescribeInternetGateways",
                              hash_params('InternetGatewayId', list.to_a))
      request_cache_or_info(:describe_internet_gateways, link,
                            QEc2DescribeInternetGatewaysParser,
                            @@bench, list.nil? || list.empty?)
    rescue
      on_exception
    end

    def delete_internet_gateway(internet_gateway_id)
      link = generate_request("DeleteInternetGateway",
                              "InternetGatewayId" => internet_gateway_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def attach_internet_gateway(internet_gateway_id, vpc_id)
      link = generate_request("AttachInternetGateway",
                              "InternetGatewayId" => internet_gateway_id,
                              "VpcId" => vpc_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def detach_internet_gateway(internet_gateway_id, vpc_id)
      link = generate_request("DetachInternetGateway",
                              "InternetGatewayId" => internet_gateway_id,
                              "VpcId" => vpc_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # RouteTable APIs
    def create_route_table(vpc_id)
      link = generate_request("CreateRouteTable", "VpcId" => vpc_id)
      request_info(link, QEc2CreateRouteTableParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def associate_route_table(route_table_id, subnet_id)
      link = generate_request("AssociateRouteTable",
                              "RouteTableId" => route_table_id,
                              "SubnetId" => subnet_id)
      request_info(link, QEc2AssociateRouteTableParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def disassociate_route_table(association_id)
      link = generate_request("DisassociateRouteTable",
                              "AssociationId" => association_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def delete_route_table(route_table_id)
      link = generate_request("DeleteRouteTable",
                              "RouteTableId" => route_table_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def describe_route_tables(list=[], filter={})
      link = generate_request("DescribeRouteTables",
                              hash_params('RouteTableId', list.to_a).merge(filter))
      request_cache_or_info(:describe_internet_gateways, link,
                            QEc2DescribeRouteTablesParser,
                            @@bench, list.nil? || list.empty?)
    rescue
      on_exception
    end

    def replace_route_table_association(association_id, route_table_id)
      link = generate_request("ReplaceRouteTableAssociation",
                              "AssociationId" => association_id,
                              "RouteTableId" => route_table_id)
      request_info(link, QEc2ReplaceRouteTableParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def create_route(route_table_id, dest_cidr_block, gateway_id=nil, instance_id=nil, network_interface_id=nil)
      link = generate_request("CreateRoute",
                              "RouteTableId" => route_table_id,
                              "DestinationCidrBlock" => dest_cidr_block,
                              "GatewayId" => gateway_id,
                              "InstanceId" => instance_id,
                              "NetworkInterfaceId" => network_interface_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def delete_route(route_table_id, dest_cidr_block)
      link = generate_request("DeleteRoute",
                              "RouteTableId" => route_table_id,
                              "DestinationCidrBlock" => dest_cidr_block)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    def replace_route(route_table_id, dest_cidr_block, gateway_id=nil, instance_id=nil, network_interface_id=nil)
      link = generate_request("ReplaceRoute",
                              "RouteTableId" => route_table_id,
                              "DestinationCidrBlock" => dest_cidr,
                              "GatewayId" => gateway_id,
                              "InstanceId" => instance_id,
                              "NetworkInterfaceId" => network_interface_id)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue
      on_exception
    end

    # Gateway Parsers
    class QEc2CreateInternetGatewayParser < Aws::AwsParser
      def tagend(name)
        @result = {:internet_gateway_id => @text} if name == 'internetGatewayId'
      end
    end

    class QEc2DescribeInternetGatewaysParser < Aws::AwsParser
      def reset
        @result = []
      end
      def tagend(name)
        case name
        when 'internetGatewayId' then
          @gateway[:internet_gateway_id] = @text
        when 'vpcId' then
          @attachment[:vpc_id] = @text
        when 'state' then
          @attachment[:state] = @text
        when 'item' then
          if @xmlpath == 'DescribeInternetGatewaysResponse/internetGatewaySet/item/attachmentSet'
            @gateway[:attachments] << @attachment
          elsif @xmlpath == 'DescribeInternetGatewaysResponse/internetGatewaySet'
            @result << @gateway
          end
        end
      end
      def tagstart(name, attributes)
        if name == 'item' && @xmlpath[%r{.*/internetGatewaySet/item/attachmentSet$}]
          @attachment = {}
        elsif name == 'item' && @xmlpath[%r{.*/internetGatewaySet$}]
          @gateway = {
            :attachments => []
          }
        end
      end
    end

    # RouteTable Parsers
    class QEc2CreateRouteTableParser < Aws::AwsParser
      def reset
        @result = {
          :routes => []
        }
      end
      def tagend(name)
        case name
        when 'routeTableId' then
          @result[:route_table_id] = @text
        when 'vpcId' then
          @result[:vpc_id] = @text
        when 'destinationCidrBlock' then
          @route[:destination_cidr_block] = @text
        when 'gateway_id' then
          @route[:gateway_id] = @text
        when 'state' then
          @route[:state] = @text
        when 'item' then
          if @xmlpath == 'CreateRouteTableResponse/routeTable/routeSet'
            @result[:routes] << @route
          end
        end
      end
      def tagstart(name, attributes)
        if name == 'item' && @xmlpath[%r{.*/routeSet$}]
          @route = {}
        end
      end
    end

    class QEc2AssociateRouteTableParser < Aws::AwsParser
      def tagend(name)
        @result = @text if name == 'associationId'
      end
    end

    class QEc2DescribeRouteTablesParser < Aws::AwsParser
      def reset
        @result = []
      end
      def tagend(name)
        case name
        when 'routeTableId' then
          if @xmlpath == 'DescribeRouteTablesResponse/routeTableSet/item'
            @route_table[:route_table_id] = @text
          elsif @xmlpath == 'DescribeRouteTablesResponse/routeTableSet/item/associationSet/item'
            @association[:route_table_id] = @text
          end
        when 'vpcId' then
          @route_table[:vpc_id] = @text
        when 'destinationCidrBlock' then
          @route[:destination_cidr_block] = @text
        when 'gatewayId' then
          @route[:gateway_id] = @text
        when 'state' then
          @route[:state] = @text
        when 'origin' then
          @route[:origin] = @text
        when 'routeTableAssociationId' then
          @association[:route_table_association_id] = @text
        when 'main' then
          @association[:main] = @text
        when 'subnetId' then
          @association[:subnet_id] = @text
        when 'item' then
          if @xmlpath == 'DescribeRouteTablesResponse/routeTableSet'
            @result << @route_table
          elsif @xmlpath == 'DescribeRouteTablesResponse/routeTableSet/item/routeSet'
            @route_table[:routes] << @route
          elsif @xmlpath == 'DescribeRouteTablesResponse/routeTableSet/item/associationSet'
            @route_table[:associations] << @association
          end
        end
      end
      def tagstart(name, attributes)
        if name == 'item' && @xmlpath[%r{.*/routeTableSet$}]
          @route_table = {
            :routes => [],
            :associations => []
          }
        elsif name == 'item' && @xmlpath[%r{.*/routeTableSet/item/routeSet$}]
          @route = {}
        elsif name == 'item' && @xmlpath[%r{.*/routeTableSet/item/associationSet$}]
          @association = {}
        end
      end
    end

    class QEc2ReplaceRouteTableiAssociationParser < Aws::AwsParser
      def tagend(name)
        @result = @text if name == 'newAssociationid'
      end
    end

    def launch_instances(image_id, options={})
      @logger.info("Launching instance of image #{image_id} for #{@aws_access_key_id}, " +
                       "key: #{options[:key_name]}, groups: #{(options[:group_ids]).to_a.join(',')}")
      # careful: keyName and securityGroups may be nil
      params = hash_params('SecurityGroupId', options[:group_ids].to_a)
      params.update({'ImageId'        => image_id,
                     'MinCount'       => (options[:min_count] || 1).to_s,
                     'MaxCount'       => (options[:max_count] || 1).to_s,
                     'AddressingType' => options[:addressing_type] || DEFAULT_ADDRESSING_TYPE,
                     'InstanceType'   => options[:instance_type] || DEFAULT_INSTANCE_TYPE})
      # optional params
      params['KeyName'] = options[:key_name] unless Aws::Utils.blank?(options[:key_name])
      params['KernelId'] = options[:kernel_id] unless Aws::Utils.blank?(options[:kernel_id])
      params['RamdiskId'] = options[:ramdisk_id] unless Aws::Utils.blank?(options[:ramdisk_id])
      params['Placement.AvailabilityZone'] = options[:availability_zone] unless Aws::Utils.blank?(options[:availability_zone])
      params['BlockDeviceMappings'] = options[:block_device_mappings] unless Aws::Utils.blank?(options[:block_device_mappings])
      params['Monitoring.Enabled'] = options[:monitoring_enabled] unless Aws::Utils.blank?(options[:monitoring_enabled])
      params['SubnetId'] = options[:subnet_id] unless Aws::Utils.blank?(options[:subnet_id])
      params['AdditionalInfo'] = options[:additional_info] unless Aws::Utils.blank?(options[:additional_info])
      params['DisableApiTermination'] = options[:disable_api_termination].to_s unless options[:disable_api_termination].nil?
      params['InstanceInitiatedShutdownBehavior'] = options[:instance_initiated_shutdown_behavior] unless Aws::Utils.blank?(options[:instance_initiated_shutdown_behavior])
      unless Aws::Utils.blank?(options[:user_data])
        options[:user_data].strip!
        # Do not use CGI::escape(encode64(...)) as it is done in Amazons EC2 library.
        # Amazon 169.254.169.254 does not like escaped symbols!
        # And it doesn't like "\n" inside of encoded string! Grrr....
        # Otherwise, some of UserData symbols will be lost...
        params['UserData'] = Base64.encode64(options[:user_data]).delete("\n").strip unless Aws::Utils.blank?(options[:user_data])
      end
      unless Aws::Utils.blank?(options[:block_device_mappings])
        options[:block_device_mappings].size.times do |n|
          if options[:block_device_mappings][n][:virtual_name]
            params["BlockDeviceMapping.#{n+1}.VirtualName"] = options[:block_device_mappings][n][:virtual_name]
          end
          if options[:block_device_mappings][n][:device_name]
            params["BlockDeviceMapping.#{n+1}.DeviceName"] = options[:block_device_mappings][n][:device_name]
          end
          if options[:block_device_mappings][n][:ebs_snapshot_id]
            params["BlockDeviceMapping.#{n+1}.Ebs.SnapshotId"] = options[:block_device_mappings][n][:ebs_snapshot_id]
          end
        end
      end
      link      = generate_request("RunInstances", params)
      #debugger
      instances = request_info(link, QEc2DescribeInstancesParser.new(:logger => @logger))
      get_desc_instances(instances)
    rescue Exception
      on_exception
    end

    class QEc2IpPermissionType #:nodoc:
      attr_accessor :ipProtocol
      attr_accessor :fromPort
      attr_accessor :toPort
      attr_accessor :groups
      attr_accessor :ipRanges
      attr_accessor :direction
    end

    class QEc2DescribeSecurityGroupsParser < Aws::AwsParser #:nodoc:
      def tagstart(name, attributes)
        case name
          when 'item'
            if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo'
              @group               = QEc2SecurityGroupItemType.new
              @group.ipPermissions = []
            elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress'
              @perm          = QEc2IpPermissionType.new
              @perm.ipRanges = []
              @perm.groups   = []
              if @xmlpath =~ /ipPermissions$/
                @perm.direction = 'ingress'
              elsif @xmlpath =~ /ipPermissionsEgress$/
                @perm.direction = 'egress'
              end
            elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress/item/groups'
              @sgroup = QEc2UserIdGroupPairType.new
            elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/ipRanges' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress/item/ipRanges'
              @sIpRange = QEc2IpRangeItemType.new
            end
        end
      end

      def tagend(name)
        case name
        when 'ownerId'          then @group.ownerId   = @text
        when 'groupDescription' then @group.groupDescription = @text
        when 'groupName'
          if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item'
            @group.groupName  = @text
          elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups/item' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress/item/groups/item'

            @sgroup.groupName = @text
          end
        when 'ipProtocol'       then @perm.ipProtocol = @text
        when 'fromPort'         then @perm.fromPort   = @text
        when 'toPort'           then @perm.toPort     = @text
        when 'userId'           then @sgroup.userId   = @text
        when 'cidrIp'           then @sIpRange.cidrIp = @text
        when 'item'
          if @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/groups' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress/item/groups'
            @perm.groups << @sgroup
          elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions/item/ipRanges' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress/item/ipRanges'
            @perm.ipRanges << @sIpRange
          elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissions' || @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo/item/ipPermissionsEgress'
            @group.ipPermissions << @perm
          elsif @xmlpath=='DescribeSecurityGroupsResponse/securityGroupInfo'
            @result << @group
          end
        end
      end

      def reset
        @result = []
      end
    end

    class QEc2CreateSecurityGroupParser < Aws::AwsParser
      def initialize(opts = {})
        super(opts)
        @level = ['top']
      end

      def tagend(name)
        case name
        when 'groupId' then
          @result['groupId'] = @text
        end
      end

      def reset
        @result = {}
      end
    end

    def create_security_group(name, description, vpcid)
      # EC2 doesn't like an empty description...
      description = " " if Aws::Utils.blank?(description)
      link = generate_request("CreateSecurityGroup",
                              'GroupName'        => name.to_s,
                              'GroupDescription' => description.to_s,
                              'VpcId' => vpcid)

      request_info(link, QEc2CreateSecurityGroupParser.new)
    rescue Exception
      on_exception
    end

    def delete_security_group(name)
      link = generate_request("DeleteSecurityGroup",
                              'GroupId' => name.to_s)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    def manage_security_group_ingress(name, from_port, to_port, protocol, action, source_ip_ranges, source_groups = [])
      call_params = {  'GroupId'   => name.to_s,
                      'IpPermissions.1.IpProtocol' => protocol.to_s,
                       'IpPermissions.1.FromPort'   => from_port.to_s,
                       'IpPermissions.1.ToPort'     => to_port.to_s  }

      source_ip_ranges.each_index do |i|
        call_params.merge!({"IpPermissions.1.IpRanges.#{i+1}.CidrIp" => source_ip_ranges[i].to_s})
      end
      source_groups.each_index do |i|
        call_params.merge!({"IpPermissions.1.Groups.#{i+1}.GroupName" => source_groups[i]['group_name'].to_s,
                            "IpPermissions.1.Groups.#{i+1}.UserId"=> source_groups[i]['owner'].to_s.gsub(/-/,'')})
      end
      unless ['Authorize', 'Revoke'].include?(action.capitalize)
         raise AwsError.new("Invalid action #{action} - must be one of \'Authorize\' or \'Revoke\'")
      end

      link = generate_request("#{action.capitalize}SecurityGroupIngress", call_params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    def describe_security_groups(list=[])
      link = generate_request("DescribeSecurityGroups", hash_params('GroupId', list.to_a))
      request_cache_or_info(:describe_security_groups, link, QEc2DescribeSecurityGroupsParser, @@bench, false) do |parser|
      result = []
      parser.result.each do |item|
        perms = []
        item.ipPermissions.each do |perm|
          current = {:from_port => perm.fromPort,
                     :to_port => perm.toPort,
                     :protocol => perm.ipProtocol,
                     :direction => perm.direction,
                     :groups => [], :ip_ranges => []}
          perm.groups.each do |ngroup|
             current[:groups] << {:group_name => ngroup.groupName, :owner => ngroup.userId}
          end
          perm.ipRanges.each do |cidr_ip|
             current[:ip_ranges] << {:cidr_ip => cidr_ip.cidrIp}
          end
        perms << current
        end
        result << {:aws_owner       => item.ownerId,
                   :aws_group_name  => item.groupName,
                   :aws_description => item.groupDescription,
                   :aws_perms       => perms}
        end
        result
      end
    rescue Exception
      on_exception
    end

    def manage_security_group_egress(name, from_port, to_port, protocol, action, source_ip_ranges, source_groups = [])
      call_params = {  'GroupId'   => name.to_s,
                      'IpPermissions.1.IpProtocol' => protocol.to_s,
                       'IpPermissions.1.FromPort'   => from_port.to_s,
                       'IpPermissions.1.ToPort'     => to_port.to_s  }
      source_ip_ranges.each_index do |i|
        call_params.merge!({"IpPermissions.1.IpRanges.#{i+1}.CidrIp" => source_ip_ranges[i].to_s})
      end
      source_groups.each_index do |i|
        call_params.merge!({"IpPermissions.1.Groups.#{i+1}.GroupName" => source_groups[i]['group_name'].to_s,
                            "IpPermissions.1.Groups.#{i+1}.UserId"=> source_groups[i]['owner'].to_s.gsub(/-/,'')})
      end
      unless ['Authorize', 'Revoke'].include?(action.capitalize)
         raise AwsError.new("Invalid action #{action} - must be one of \'Authorize\' or \'Revoke\'")
      end
      link = generate_request("#{action.capitalize}SecurityGroupEgress", call_params)
      request_info(link, RightBoolResponseParser.new(:logger => @logger))
    rescue Exception
      on_exception
    end

    def attach_volume(volume_id, instance_id, device)
      # ignore "device" parameter at this time.
      # try to create volume like /dev/sda, /dev/sdb..., /dev/sdz
      code = 97 # 'a'
      begin
        device = "/dev/sd#{code.chr}"
        link = generate_request("AttachVolume",
                                "VolumeId"   => volume_id.to_s,
                                "InstanceId" => instance_id.to_s,
                                "Device"     => device)
        request_info(link, QEc2AttachAndDetachVolumeParser.new(:logger => @logger))

      rescue Aws::AwsError => e
        if e.message =~ /InvalidParameterValue/ && code <= 122 # 'z'
          sleep 1
          code += 1
          retry
        else
          raise
        end
      rescue Exception
        on_exception
      end
    end
  end
end
