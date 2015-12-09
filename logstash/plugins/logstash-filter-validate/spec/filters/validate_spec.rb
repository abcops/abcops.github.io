# encoding: utf-8
require 'spec_helper'
require "logstash/filters/validate"

describe LogStash::Filters::Validate do
  describe "configutaion" do
    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "/opt/logstash/validate/validate.out"
        }
      }
    CONFIG
    end

  end
end
