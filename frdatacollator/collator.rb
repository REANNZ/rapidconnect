require 'net/http'
require 'openssl'
require 'addressable/uri'
require 'json'
require 'yaml'

##
# Grab all organisations currently in FR for users to select when registering services
##
def secure_server_request(uri)
  http = Net::HTTP.new @config['server'], 443
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  req = Net::HTTP::Get.new uri
  response = http.request req

  case response
    when Net::HTTPSuccess
      response.body
    else
      raise "Invalid FR response for API call #{response.value}"
  end
end

@config = YAML.load_file('config.yml')

target_file = @config['target_file'] || '/opt/rapidconnect/application/run/fr_org_names.json.new'
org_names = []
fr_response = secure_server_request Addressable::URI.encode @config['org_api_endpoint']
fr_json = JSON.parse fr_response

fr_json["organizations"].each { |org|
  fr_org_json = JSON.parse(secure_server_request org['link'])
  org_names << fr_org_json['organization']['displayName']
}

File.open(target_file, 'w') {|f| f.write( JSON.generate org_names.sort! ) }

