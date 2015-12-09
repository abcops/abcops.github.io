# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

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
  

  public
  def register
    # hash that will store the validation data
    @keyhash = Hash.new

    load_validate_file()

    @logger.info("validate_file", @keyhash)

  end # def register

  public
  def filter(event)

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
