#
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
# 2014.03.24 TIS inc. : Implement OpenStack FloatingIP function.

module Deltacloud
  class Address < BaseModel
    attr_accessor :instance_id
    attr_accessor :ip_address

    def initialize(init=nil)
      super(init)
    end

    def associated?
      !self.instance_id.nil?
    end

    def to_hash(context)
      r = {
        :id => self.id,
        :href => context.address_url(self.id),
        :associated => associated?
      }
      r[:instance_id] = instance_id if associated?
      r[:ip_address] = ip_address unless ip_address.nil?
      r
    end

  end
end
