# encoding: utf-8
require 'spec_helper'
require "tempfile"
require "stud/temporary"
require "logstash/filters/validate"

# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
end

describe LogStash::Filters::Validate do
  describe "it should work" do

    tmpfile_path = Stud::Temporary.pathname
 
    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample("test1" => "1", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] }.nil?
      insist { subject["test1"] } == "1"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end

  describe "it should fail" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
        }
      }
    CONFIG
    end

    sample("test1" => "2", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] }  == ["_validationerror"]
      insist { subject["test1"] } == "2"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end

  describe "test tag on failure" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          tag_on_failure => "_newtag"
        }
      }
    CONFIG
    end

    sample("test1" => "2", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] }  == ["_newtag"]
      insist { subject["test1"] } == "2"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end
end
