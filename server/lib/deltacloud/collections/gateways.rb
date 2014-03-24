
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

module Deltacloud::Collections
  class Gateways < Base

    include Deltacloud::Features

    set :capability, lambda { |m| driver.respond_to? m }
    check_features :for => lambda { |c, f| driver.class.has_feature?(c, f) }

    collection :gateways do
      standard_show_operation
      standard_index_operation

      operation :create, :with_capability => :create_gateway do
        param :name,           :string, :optional
        control do
          @gateway = driver.create_gateway(credentials, params)
          respond_to do |format|
            format.xml  { haml :"gateways/show" }
            format.html { haml :"gateways/show" }
            format.json { JSON::dump(:gateway => @gateway.to_hash(self)) }
          end
        end
      end

      operation :destroy, :with_capability => :destroy_gateway do
        param :id, :string, :required
        control do
          driver.destroy_gateway(credentials, params[:id])
          status 204
          respond_to do |format|
            format.xml
            format.json
            format.html { redirect(gateway_url) }
          end
        end
      end

      action :attach, :http_method => :put, :with_capability => :attach_gateway do
        description "Attach a gateway to external network."
        param :id, :string, :required
        param :network_id, :string, :required
        control do
          driver.attach_gateway(credentials, params)
          status 204
          respond_to do |format|
            format.xml
            format.html
            format.json { redirect(gateway_url(params[:id])) }
          end
        end
      end

      action :detach, :http_method => :put, :with_capability => :detach_gateway do
        description "Dettach a gateway from external network."
        param :id, :string, :required
        control do
          driver.detach_gateway(credentials, params)
          status 204
          respond_to do |format|
            format.xml
            format.html
            format.json { redirect(gateway_url(params[:id])) }
          end
        end
      end

      action :add_interface, :http_method => :put, :with_capability => :add_interface_to_gateway do
        description "Add specified subnet interface or route to Gateway."
        param :id, :string, :required
        param :subnet_id, :string, :required
        control do
          driver.add_interface_to_gateway(credentials, params)
          status 204
          respond_to do |format|
            format.xml
            format.json
            format.html { redirect(gateway_url(params[:id])) }
          end
        end
      end

      action :remove_interface, :http_method => :put, :with_capability => :remove_interface_from_gateway do
        description "Remove specified subnet interface or route from Gateway."
        param :id, :string, :required
        param :subnet_id, :string, :optional
        control do
          driver.remove_interface_from_gateway(credentials, params)
          status 204
          respond_to do |format|
            format.xml
            format.json
            format.html { redirect(gateway_url(params[:id])) }
          end
        end
      end

    end

  end
end
