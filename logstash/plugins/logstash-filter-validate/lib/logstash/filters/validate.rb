# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require "json"

# This class is used to validate fields defined after a reindex
class LogStash::Filters::Validate < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   validate {
  #     validate_file => "/opt/logstash/validate/validate.out"
  #   }
  # }
  #
  config_name "validate"
  
  # define the location of the validate file
  config :validate_file, :validate => :string, :default => "/opt/logstash/validate/validate.out"

  # Append values to the `tags` field when there has been no
  # successful match
  config :tag_on_failure, :validate => :array, :default => ["_validationerror"]
  

  public
  def register

    # hash that will store the validation data
    @keyhash = Hash.new

    load_validate_file()

    @logger.debug("validate_file", @keyhash)

    if @keyhash.empty?
      @logger.error("Unable to parse validation file")
    end

  end # def register

  public
  def filter(event)

    errorflag=false

    getjson = @keyhash[event["path"]]
        
    if getjson.nil?
      @logger.error("key does not exists in #{@validate_file} ", event["path"])
      errorflag=true
    else 
      begin
        getjson.each do |k,v|
          if event["type"] !~ /access[.-]log/ and event["type"] !~ /error[.-]log/
            if event[k] != v
              errorflag=true
            end
          else
            if k != "type" and k != "host"
              if k == "zone"
                if event["host"] =~ /^inw/
                  if event["zone"] != "red"
                    errorflag=true
                  end
                elsif event["host"] =~ /^nuc/
                  if event["zone"] != "blue"
                    errorflag=true
                  end
                end
              else
                if event[k] != v
                  errorflag=true
                end
              end
            end
          end
        end
      rescue
        @logger.error("Unable to determine valid data")
        errorflag=true
      end
    end
        
    if errorflag 
      @tag_on_failure.each do |tag|
        event["tags"] ||= []
        event["tags"] << tag unless event["tags"].include?(tag)
      end
    end
 
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  private
    def load_validate_file()
      begin
        file = File.read(@validate_file)
        file.each_line do |line|
          json_line = JSON.parse(line)
          @keyhash[json_line["path"]] = json_line
        end
      rescue StandardError => e
        @logger.error("load_validate_file threw exception", :exception => e.message)
      end
    end

end # class LogStash::Filters::Validate
