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
      fd.puts("{ \"path\": \"1\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => 'path'
          tag_on_success => "_success"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "test1" => "1", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] } == [ "_success" ]
      insist { subject["test1"] } == "1"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end

  describe "it should fail" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "test1" => "2", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] }  == ["_errorcode_2"]
      insist { subject["test1"] } == "2"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end

  describe "test tag on failure" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          tag_on_failure => "_newtag"
        }
      }
    CONFIG
    end

    sample("path" => "1", "test1" => "2", "test2" => "2", "test3" => "3") do
      insist { subject["tags"] }  == ["_newtag"]
      insist { subject["test1"] } == "2"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end

  end

  describe "Test red zone failure" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"type\": \"access.log\", \"host\": \"inwtest01\", \"zone\": \"localhost\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "type" => "access.log", "host" => "inwtest01", "zone" => "notred") do
      insist { subject["tags"] }  == ["_errorcode_4"]
    end
  end

  describe "test zone red success" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"type\": \"access.log\", \"host\": \"inwtest01\", \"zone\": \"localhost\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "type" => "access.log", "host" => "inwtest01", "zone" => "red",  "test1" => "1", "test2" => "2", "test3" => "3") do
      insist { subject["path"] } == "1"
      insist { subject["type"] } == "access.log"
      insist { subject["host"] } == "inwtest01"
      insist { subject["zone"] } == "red"
      insist { subject["test1"] } == "1"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end
  end

  describe "test zone blue failure" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"type\": \"access.log\", \"host\": \"nuctest01\", \"zone\": \"localhost\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "type" => "access.log", "host" => "nuctest01", "zone" => "notblue", "test1" => "1", "test2" => "2", "test3" => "3") do
      insist { subject["path"] } == "1"
      insist { subject["type"] } == "access.log"
      insist { subject["host"] } == "nuctest01"
      insist { subject["zone"] } == "notblue"
      insist { subject["tags"] } == ["_errorcode_8"]
    end
  end  

describe "test zone blue success" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"type\": \"access.log\", \"host\": \"nuctest01\", \"zone\": \"localhost\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "type" => "access.log", "host" => "nuctest01", "zone" => "blue", "test1" => "1", "test2" => "2", "test3" => "3") do
      insist { subject["path"] } == "1"
      insist { subject["type"] } == "access.log"
      insist { subject["host"] } == "nuctest01"
      insist { subject["zone"] } == "blue"
      insist { subject["test1"] } == "1"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
    end
  end

  describe "access.log failure" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"path\": \"1\", \"type\": \"access.log\", \"host\": \"nuctest01\", \"zone\": \"localhost\", \"test1\": \"1\", \"test2\": \"2\", \"test3\": \"3\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("path" => "1", "type" => "access.log", "host" => "nuctest01", "zone" => "blue", "test1" => "2", "test2" => "2", "test3" => "3") do
      insist { subject["path"] } == "1"
      insist { subject["type"] } == "access.log"
      insist { subject["host"] } == "nuctest01"
      insist { subject["zone"] } == "blue"
      insist { subject["test1"] } == "2"
      insist { subject["test2"] } == "2"
      insist { subject["test3"] } == "3"
      insist { subject["tags"] }  == ["_errorcode_16"]
    end
  end

  describe "cause malfuntion when target does not exists" do

    tmpfile_path = Stud::Temporary.pathname

    File.open(tmpfile_path, "w") do |fd|
      fd.puts("{ \"test\": \"1\" }")
    end

    let(:config) do <<-CONFIG
      filter {
        validate {
          validate_file => "#{tmpfile_path}"
          target => "path"
          debug => true
        }
      }
    CONFIG
    end

    sample("test" => "1") do
      insist { subject["tags"] } == ["_errorcode_32"]
    end
  end

end
