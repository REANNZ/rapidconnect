require 'net/http'
require 'uri'
require 'json'
require 'yaml'

##
# Grab all organisations currently in FR for users to select when registering services
##
def secure_server_request(uri)
  response = Net::HTTP::get_response uri

  case response
    when Net::HTTPSuccess
      response.body
    else
      raise "Invalid FR response for API call #{response.code}"
  end
end

@config = YAML.load_file('config.yml')

target_file = @config['target_file'] || '/opt/rapidconnect/application/run/fr_org_names.json.new'
org_names = []
fr_response = secure_server_request URI(@config['org_api_url'])
fr_json = JSON.parse fr_response

fr_json["organizations"].select { |org| org['active'] }.each { |org|
  org_names << org['organizationInfoData']['en']['OrganizationDisplayName']
}

File.open(target_file, 'w') {|f| f.write( JSON.pretty_generate org_names.sort! ) }

