require 'spec_helper'
require './app/rapid_connect'

describe RapidConnect do

  before :each do
    @valid_shibboleth_headers = {
      'HTTP_SHIB_SESSION_ID' => 'abcd1234',
      'HTTP_PERSISTENT_ID' => 'https://idp.example.com!https://sp.example.com!0987zyxw',
      'HTTP_CN' => 'Test User',
      'HTTP_DISPLAYNAME' => 'Mr Test J User',
      'HTTP_GIVENNAME' => 'Test',
      'HTTP_SN' => 'User',
      'HTTP_MAIL' => 'testuser@example.com',
      'HTTP_EPPN' => 'tuser1@example.com',
      'HTTP_AFFILIATION' => 'staff@example.com'
    }

    @valid_subject = {
      :principal => @valid_shibboleth_headers['HTTP_PERSISTENT_ID'],
      :cn => @valid_shibboleth_headers['HTTP_CN'],
      :display_name => @valid_shibboleth_headers['HTTP_DISPLAYNAME'],
      :given_name => @valid_shibboleth_headers['HTTP_GIVENNAME'],
      :surname => @valid_shibboleth_headers['HTTP_SN'],
      :mail => @valid_shibboleth_headers['HTTP_MAIL'],
      :principal_name => @valid_shibboleth_headers['HTTP_EPPN'],
      :scoped_affiliation => @valid_shibboleth_headers['HTTP_AFFILIATION']
    }

    @redis =  Redis.new
  end

  after :each do
    flush_stores
  end

  def administrator
    @redis.hset('administrators', @valid_subject[:principal], {'name' => @valid_subject[:cn], 'mail' => @valid_subject[:mail] }.to_json)
  end

  def exampleservice
    @redis.hset('serviceproviders', '1234abcd', {'name'=>'Our Web App', 'audience'=>'https://service.com', 'endpoint'=>'https://service.com/auth/jwt', 'secret'=>'ykUlP1XMq3RXMd9w'}.to_json)
  end

  def enableexampleservice
    exampleservice
    service_provider = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    service_provider[:enabled] = true
    @redis.hset('serviceproviders', '1234abcd', service_provider.to_json)
  end

  it "shows welcome erb for root level request" do
    get '/'
    last_response.should be_ok
    last_response.body.should contain('Welcome to AAF Rapid Connect')
  end

  it "redirects to Shibboleth SP SSO on login request" do
    get '/login'
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/Shibboleth.sso/Login?target=/login/shibboleth')
  end

  it "sends a 403 response if Shibboleth SP login response contains no session id" do
    get '/login/shibboleth', rack_env={}
    last_response.status.should eq(403)
  end

  it "sends a redirect to service unknown if original target not in session" do
    get '/login/shibboleth', {}, @valid_shibboleth_headers
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/serviceunknown')
    follow_redirect!
    last_response.body.should contain('Service Unknown')
  end

  it "sends a redirect to the original target and populates subject into session when there is a valid Shibboleth SP response" do
    target = 'http://example.org/jwt/authnrequest'
    get '/login/shibboleth', {}, {'rack.session' => { :target => target }}.merge(@valid_shibboleth_headers)
    last_response.should be_redirect
    last_response.location.should eq(target)
    session[:target].should be_nil
    session[:subject][:principal].should eq(@valid_shibboleth_headers['HTTP_PERSISTENT_ID'])
    session[:subject][:cn].should eq(@valid_shibboleth_headers['HTTP_CN'])
    session[:subject][:display_name].should eq(@valid_shibboleth_headers['HTTP_DISPLAYNAME'])
    session[:subject][:given_name].should eq(@valid_shibboleth_headers['HTTP_GIVENNAME'])
    session[:subject][:surname].should eq(@valid_shibboleth_headers['HTTP_SN'])
    session[:subject][:mail].should eq(@valid_shibboleth_headers['HTTP_MAIL'])
    session[:subject][:principal_name].should eq(@valid_shibboleth_headers['HTTP_EPPN'])
    session[:subject][:scoped_affiliation].should eq(@valid_shibboleth_headers['HTTP_AFFILIATION'])
  end

  it 'performs logout correctly' do
    get '/logout', {}, {'rack.session' => { :subject => {:cn => 'Test User'}}}
    session[:subject].should be_nil
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/')
  end

  it 'directs to login if registration attempted when unauthenticated' do
    get '/registration'
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/login')
  end

  it 'shows the registration screen' do
    get '/registration', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain('Service Registration')
  end

  it 'sends a flash message when invalid registration form data is submitted' do
    post '/registration/save', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.body.should contain('Service Registration')
    last_response.body.should contain('Invalid data supplied')
  end

  it 'sends an email and shows success page when valid registration form submitted' do
    post '/registration/save', {'name'=>'Our Web App', 'audience'=>'https://service.com', 'endpoint'=>'https://service.com/auth/jwt', 'secret'=>'ykUlP1XMq3RXMd9w'}, {'rack.session' => { :subject => @valid_subject}}

    should have_sent_email
    last_email.to('support@aaf.edu.au')
    last_email.from('noreply@aaf.edu.au')
    last_email.subject('New service registration for AAF Rapid Connect')
    last_email.html_part.should contain(@valid_subject[:cn])

    @redis.hlen('serviceproviders').should eq(1)
    service = JSON.parse(@redis.hvals('serviceproviders')[0])
    service['name'].should eq('Our Web App')
    service['endpoint'].should eq('https://service.com/auth/jwt')
    service['secret'].should eq('ykUlP1XMq3RXMd9w')
    service['enabled'].should be_false

    last_response.should be_redirect
    last_response.location.should eq('http://example.org/registration/complete')
    follow_redirect!
    last_response.body.should contain('Service Registration Complete')
  end

  it 'directs to login if administration url requested when unauthenticated' do
    get '/administration/xyz'
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/login')
  end

  it 'halts with 403 if administration url requested when authenticated user is not an administrator' do
    get '/administration/xyz', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(403)
  end

  it 'shows the administration dashboard' do
    administrator
    get '/administration', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain('Administration')
  end

  it 'lists all current services' do
    exampleservice
    administrator
    get '/administration/services', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(200)
    last_response.should contain('Our Web App')
    last_response.should contain('Show')
  end

  it 'sends 404 when an invalid service is requested' do
    administrator
    get '/administration/services/invalidid', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(404)
  end

  it 'shows a specific service' do
    exampleservice
    administrator
    get '/administration/services/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(200)
    last_response.should contain('Our Web App')
    last_response.should contain('Edit')
    last_response.should contain('Delete')
  end

  it 'sends 404 when an invalid service is edited' do
    administrator
    get '/administration/edit/invalidid', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(404)
  end

  it 'edits a specific service' do
    exampleservice
    administrator
    get '/administration/services/edit/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(200)
    last_response.should contain('Editing Our Web App')
    last_response.should contain('Update Service')
    last_response.should contain('Cancel')
  end

  it 'provides an error when invalid service is provided in update' do
    exampleservice
    administrator

    put '/administration/services/update', {'identifier' => 'xyz'}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services')
    follow_redirect!
    last_response.body.should contain('Invalid data supplied')
  end

  it 'provides an error when invalid service data is provided in update' do
    exampleservice
    administrator

    put '/administration/services/update', {'identifier' => '1234abcd','name'=>'Our Web App'}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services')
    follow_redirect!
    last_response.body.should contain('Invalid data supplied')
  end

  it 'successfully updates services' do
    exampleservice
    administrator

    current_service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    current_service['name'].should eq('Our Web App')
    current_service['audience'].should eq('https://service.com')
    current_service['endpoint'].should eq('https://service.com/auth/jwt')
    current_service['secret'].should eq('ykUlP1XMq3RXMd9w')
    !current_service['enabled']

    put '/administration/services/update', {'identifier' => '1234abcd', 'name'=>'Our Web App2', 'audience'=>'https://service2.com',
                                            'endpoint'=>'https://service.com/auth/jwt2', 'secret'=>'ykUlP1XMq3RXMd9w2',
                                            'enabled'=>'on', 'registrant_name'=>'Dummy User', 'registrant_mail'=>'dummy@example.org'},
                                            {'rack.session' => { :subject => @valid_subject}}

    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services/1234abcd')

    updated_service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    updated_service['name'].should eq('Our Web App2')
    updated_service['audience'].should eq('https://service2.com')
    updated_service['endpoint'].should eq('https://service.com/auth/jwt2')
    updated_service['secret'].should eq('ykUlP1XMq3RXMd9w2')
    updated_service['enabled']
  end

  it 'successfully toggles service state' do
    exampleservice
    administrator

    service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    service['enabled'].should be_false

    # Toggle On
    patch '/administration/services/toggle/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services/1234abcd')
    service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    service['enabled'].should be_true

    # Toggle back off
    patch '/administration/services/toggle/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services/1234abcd')
    service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    service['enabled'].should be_false
  end

  it 'prevents service delete if no identifier' do
    administrator
    delete '/administration/services/delete/xyz', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(404)
  end

  it 'deletes a service' do
    exampleservice
    administrator

    @redis.hlen('serviceproviders').should eq(1)
    delete '/administration/services/delete/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should eq('http://example.org/administration/services')
    @redis.hlen('serviceproviders').should eq(0)
  end

  it 'lists all current administrators' do
    administrator
    get '/administration/administrators', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain(@valid_subject[:principal])
    last_response.body.should contain("Delete")
  end

  it 'allows administrators to be created' do
    administrator
    get '/administration/administrators/create', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain('Create Administrator')
  end

  it 'prevents new administrator if no identifier' do
    administrator
    post '/administration/administrators/save', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain('Invalid form data')
  end

  it 'prevents duplicate administrators from being saved' do
    administrator
    @redis.hset('administrators', 'https://idp.example.com!https://sp.example.com!dummy', {'name' => 'Dummy User', 'mail' => 'dummy@example.org' }.to_json)

    post '/administration/administrators/save', {'identifier' => 'https://idp.example.com!https://sp.example.com!dummy'}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/administration/administrators')
    follow_redirect!
    last_response.body.should contain('Administrator already exists')
  end

  it 'prevents new administrator if name and mail not supplied' do
    administrator
    post '/administration/administrators/save', {'identifier' => 'https://idp.example.com!https://sp.example.com!dummy', 'name'=>''}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_ok
    last_response.body.should contain('Invalid form data')
  end

  it 'creates new administrator' do
    administrator
    @redis.hlen('administrators').should eq(1)
    post '/administration/administrators/save', {'identifier' => 'https://idp.example.com!https://sp.example.com!dummy', 'name'=>'Dummy User', 'mail'=>'dummy@example.org'}, {'rack.session' => { :subject => @valid_subject}}
    @redis.hlen('administrators').should eq(2)
    last_response.should be_redirect
    follow_redirect!
    last_response.body.should contain('Administrator added')
  end

  it 'prevents administrator delete if no identifier' do
    administrator
    delete '/administration/administrators/delete', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/administration/administrators')
    follow_redirect!
    last_response.body.should contain('Invalid form data')
  end

  it 'prevents administrator delete if identifier matches current administrator' do
    administrator
    delete '/administration/administrators/delete', {'identifier' => @valid_subject[:principal]}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/administration/administrators')
    follow_redirect!
    last_response.body.should contain('Removing your own access is not supported')
  end

  it 'provides an error when no such administrator is requested to be deleted' do
    administrator
    delete '/administration/administrators/delete', {'identifier' => 'https://idp.example.com!https://sp.example.com!dummy'}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/administration/administrators')
    @redis.hlen('administrators').should eq(1)
    follow_redirect!
    last_response.body.should contain('No such administrator')
  end

  it 'deletes a current administrator' do
    administrator
    @redis.hset('administrators', 'https://idp.example.com!https://sp.example.com!dummy', {'name' => 'Dummy User', 'mail' => 'dummy@example.org' }.to_json)
    @redis.hlen('administrators').should eq(2)
    delete '/administration/administrators/delete', {'identifier' => 'https://idp.example.com!https://sp.example.com!dummy'}, {'rack.session' => { :subject => @valid_subject}}
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/administration/administrators')
    @redis.hlen('administrators').should eq(1)
    follow_redirect!
    last_response.body.should contain('Administrator deleted successfully')
  end

  it 'directs to login if a jwt url requested when unauthenticated' do
    get '/jwt/xyz'
    last_response.should be_redirect
    last_response.location.should eq('http://example.org/login')
  end

  it 'sends 404 if no service registered for research JWT' do
    get '/jwt/authnrequest/research/xyz', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(404)
  end

  it 'sends 403 if service registered for research JWT is not enabled' do
    exampleservice
    get '/jwt/authnrequest/research/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(403)
  end

  it 'creates a research JWT for active services' do
    enableexampleservice
    get '/jwt/authnrequest/research/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(200)
    last_response.body.should contain('AAF Rapid Connect - Redirection')
  end

  it 'sends 404 if no service registered for zendesk JWT' do
    get '/jwt/authnrequest/zendesk/xyz', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(404)
  end

  it 'sends 403 if service registered for zendesk JWT is not enabled' do
    exampleservice
    get '/jwt/authnrequest/zendesk/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(403)
  end

  it 'creates a zendesk JWT for active services' do
    enableexampleservice
    get '/jwt/authnrequest/zendesk/1234abcd', {}, {'rack.session' => { :subject => @valid_subject}}
    last_response.status.should eq(302)
    last_response.location.should contain("jwt=")
    last_response.location.should contain("return_to=")
  end

  it 'generate valid research claim' do
    rc = RapidConnect.new
    claim = rc.helpers.generate_research_claim('http://service.com', @valid_subject)
    claim[:aud].should eq('http://service.com')
    claim[:iss].should eq('https://rapid.example.org')
    claim[:sub].should eq(@valid_subject[:principal])
    claim[:'https://aaf.edu.au/attributes'][:'cn'].should eq(@valid_subject[:cn])
    claim[:'https://aaf.edu.au/attributes'][:'mail'].should eq(@valid_subject[:mail])
    claim[:'https://aaf.edu.au/attributes'][:'edupersontargetedid'].should eq(@valid_subject[:principal])
    claim[:'https://aaf.edu.au/attributes'][:'edupersonprincipalname'].should eq(@valid_subject[:principal_name])
    claim[:'https://aaf.edu.au/attributes'][:'edupersonscopedaffiliation'].should eq(@valid_subject[:scoped_affiliation])
  end

  it 'generate valid zendesk claim' do
    rc = RapidConnect.new
    claim = rc.helpers.generate_zendesk_claim('http://service.com', @valid_subject)
    claim[:aud].should eq('http://service.com')
    claim[:iss].should eq('https://rapid.example.org')
    claim[:name].should eq(@valid_subject[:cn])
    claim[:email].should eq(@valid_subject[:mail])
    claim[:external_id].should eq(@valid_subject[:principal])
  end

end



