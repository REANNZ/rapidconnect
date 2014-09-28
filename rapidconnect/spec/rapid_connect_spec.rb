require './app/rapid_connect'

describe RapidConnect do
  def stringify_keys(hash)
    hash.reduce({}) { |a, (k, v)| a.merge(k.to_s => v) }
  end

  before :all do
    File.open('/tmp/rspec_organisations.json', 'w') { |f| f.write(JSON.generate ['Test Org Name', 'Another Test Org Name']) }
  end

  after :all do
    File.delete('/tmp/rspec_organisations.json')
  end

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
      principal: @valid_shibboleth_headers['HTTP_PERSISTENT_ID'],
      cn: @valid_shibboleth_headers['HTTP_CN'],
      display_name: @valid_shibboleth_headers['HTTP_DISPLAYNAME'],
      given_name: @valid_shibboleth_headers['HTTP_GIVENNAME'],
      surname: @valid_shibboleth_headers['HTTP_SN'],
      mail: @valid_shibboleth_headers['HTTP_MAIL'],
      principal_name: @valid_shibboleth_headers['HTTP_EPPN'],
      scoped_affiliation: @valid_shibboleth_headers['HTTP_AFFILIATION']
    }

    @redis =  Redis.new
  end

  after :each do
    flush_stores
  end

  def administrator
    @redis.hset('administrators', @valid_subject[:principal], { 'name' => @valid_subject[:cn], 'mail' => @valid_subject[:mail] }.to_json)
  end

  def exampleservice
    @redis.hset('serviceproviders', '1234abcd', { 'name' => 'Our Web App', 'audience' => 'https://service.com', 'endpoint' => 'https://service.com/auth/jwt', 'secret' => 'ykUlP1XMq3RXMd9w' }.to_json)
  end

  def enableexampleservice
    exampleservice
    service_provider = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
    service_provider[:enabled] = true
    @redis.hset('serviceproviders', '1234abcd', service_provider.to_json)
  end

  describe '/' do
    it 'shows welcome erb' do
      get '/'
      expect(last_response).to be_ok
      expect(last_response.body).to contain('Welcome to AAF Rapid Connect')
    end
  end

  describe '/login' do
    it 'redirects to Shibboleth SP SSO on login request' do
      get '/login/1'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/Shibboleth.sso/Login?target=/login/shibboleth/1')
    end

    it 'sends a 403 response if Shibboleth SP login response contains no session id' do
      get '/login/shibboleth/1'
      expect(last_response.status).to eq(403)
    end

    it 'sends a redirect to service unknown if original target not in session' do
      get '/login/shibboleth/1', {}, @valid_shibboleth_headers
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/serviceunknown')
      follow_redirect!
      expect(last_response.body).to contain('Service Unknown')
    end

    it 'sends a redirect to the original target and populates subject into session when there is a valid Shibboleth SP response' do
      target = 'http://example.org/jwt/authnrequest'
      get '/login/shibboleth/1', {}, { 'rack.session' => { target: { '1' => target } } }.merge(@valid_shibboleth_headers)
      expect(last_response).to be_redirect
      expect(last_response.location).to eq(target)
      expect(session[:target]).to be_empty
      expect(session[:subject][:principal]).to eq(@valid_shibboleth_headers['HTTP_PERSISTENT_ID'])
      expect(session[:subject][:cn]).to eq(@valid_shibboleth_headers['HTTP_CN'])
      expect(session[:subject][:display_name]).to eq(@valid_shibboleth_headers['HTTP_DISPLAYNAME'])
      expect(session[:subject][:given_name]).to eq(@valid_shibboleth_headers['HTTP_GIVENNAME'])
      expect(session[:subject][:surname]).to eq(@valid_shibboleth_headers['HTTP_SN'])
      expect(session[:subject][:mail]).to eq(@valid_shibboleth_headers['HTTP_MAIL'])
      expect(session[:subject][:principal_name]).to eq(@valid_shibboleth_headers['HTTP_EPPN'])
      expect(session[:subject][:scoped_affiliation]).to eq(@valid_shibboleth_headers['HTTP_AFFILIATION'])
    end
  end

  describe '/logout' do
    it 'performs logout correctly' do
      get '/logout', {}, 'rack.session' => { subject: { cn: 'Test User' } }
      expect(session[:subject]).to be_nil
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/')
    end
  end

  describe '/registration' do
    it 'directs to login if registration attempted when unauthenticated' do
      allow(SecureRandom).to receive(:urlsafe_base64).and_return('1')
      get '/registration'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/login/1')
    end

    it 'shows the registration screen' do
      get '/registration', {}, 'rack.session' => { subject: @valid_subject }
      expect(last_response).to be_ok
      expect(last_response.body).to contain('Service Registration')
    end

    context '/save' do
      before do
        allow(SecureRandom).to receive(:urlsafe_base64).and_return(identifier)
        @valid_subject.merge!(cn: attrs[:registrant_name],
                              mail: attrs[:registrant_mail])
      end

      let(:identifier) { '1234abc' }
      let(:attrs) { attributes_for(:rapid_connect_service) }

      let(:params) do
        attrs.select do |k, _|
          %i(name audience endpoint secret organisation).include?(k)
        end
      end

      let(:rack_env) { { 'rack.session' => { subject: @valid_subject } } }

      def run
        post '/registration/save', params, rack_env
      end

      shared_examples 'a failed registration' do |opts = {}|
        it 'is rejected' do
          run
          expect(last_response.body).to contain('Service Registration')
          expect(last_response.body)
            .to contain(opts[:message] || 'Invalid data supplied')
        end

        it 'does not create a service' do
          expect { run }.not_to change { @redis.hlen('serviceproviders') }
        end
      end

      context 'with an invalid endpoint' do
        let(:attrs) do
          attributes_for(:rapid_connect_service, endpoint: 'example.com/auth')
        end

        it_behaves_like 'a failed registration'
      end

      context 'with an invalid audience' do
        let(:attrs) do
          attributes_for(:rapid_connect_service, audience: 'example.com/auth')
        end

        it_behaves_like 'a failed registration'
      end

      context 'with no organisation' do
        let(:attrs) do
          attributes_for(:rapid_connect_service)
            .reject { |k, _| k == :organisation }
        end

        it_behaves_like 'a failed registration'
      end

      context 'when an identifier collides' do
        before do
          @redis.hset('serviceproviders', identifier, '{}')
        end

        it_behaves_like 'a failed registration',
                        message: 'Invalid identifier generated. ' \
                                 'Please re-submit registration.'
      end

      context 'with an excessively short secret' do
        let(:attrs) do
          attributes_for(:rapid_connect_service, secret: 'tooshort')
        end

        it_behaves_like 'a failed registration'
      end

      shared_examples 'a successful registration' do |opts|
        before { attrs.merge!(enabled: opts[:enabled]) }

        it 'creates the service' do
          expect { run }.to change { @redis.hlen('serviceproviders') }.by(1)
          json = @redis.hget('serviceproviders', identifier)
          expect(json).not_to be_nil

          expect(JSON.load(json)).to eq(stringify_keys(attrs))
        end

        it 'redirects to the completed registration page' do
          run
          expect(last_response).to be_redirect
          expect(last_response.location)
            .to eq('http://example.org/registration/complete')
          follow_redirect!
          expect(last_response.body).to contain(opts[:message])
        end
      end

      context 'in production' do
        before { RapidConnect.set :federation, 'production' }

        it 'sends an email' do
          run
          is_expected.to have_sent_email
          expect(last_email.to).to include('support@example.org')
          expect(last_email.from).to include('noreply@example.org')
          expect(last_email.subject)
            .to eq('New service registration for AAF Rapid Connect')
          expect(last_email.html_part).to contain(@valid_subject[:cn])
        end

        it_behaves_like 'a successful registration',
                        enabled: false,
                        message: 'Service Registration Complete'
      end

      context 'in test' do
        before { RapidConnect.set :federation, 'test' }

        it 'sends no email' do
          run
          is_expected.not_to have_sent_email
        end

        it_behaves_like 'a successful registration',
                        enabled: true,
                        message: 'Service Registered and automatically approved'
      end
    end
  end

  describe '/administration' do
    it 'directs to login if administration url requested when unauthenticated' do
      allow(SecureRandom).to receive(:urlsafe_base64).and_return('1')
      get '/administration/xyz'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/login/1')
    end

    it 'halts with 403 if administration url requested when authenticated user is not an administrator' do
      get '/administration/xyz', {}, 'rack.session' => { subject: @valid_subject }
      expect(last_response.status).to eq(403)
    end

    it 'shows the administration dashboard' do
      administrator
      get '/administration', {}, 'rack.session' => { subject: @valid_subject }
      expect(last_response).to be_ok
      expect(last_response.body).to contain('Administration')
    end

    describe '/services' do
      it 'lists all current services' do
        exampleservice
        administrator
        get '/administration/services', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(200)
        expect(last_response).to contain('Our Web App')
        expect(last_response).to contain('Show')
      end

      it 'sends 404 when an invalid service is requested' do
        administrator
        get '/administration/services/invalidid', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'shows a specific service' do
        exampleservice
        administrator
        get '/administration/services/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(200)
        expect(last_response).to contain('Our Web App')
        expect(last_response).to contain('Edit')
        expect(last_response).to contain('Delete')
      end

      it 'sends 404 when an invalid service is edited' do
        administrator
        get '/administration/edit/invalidid', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'edits a specific service' do
        exampleservice
        administrator
        get '/administration/services/edit/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(200)
        expect(last_response).to contain('Editing Our Web App')
        expect(last_response).to contain('Update Service')
        expect(last_response).to contain('Cancel')
      end

      it 'returns 404 on invalid service' do
        administrator
        get '/administration/services/edit/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'provides an error when invalid service is provided in update' do
        exampleservice
        administrator

        put '/administration/services/update', { 'identifier' => 'xyz' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services')
        follow_redirect!
        expect(last_response.body).to contain('Invalid data supplied')
      end

      it 'provides an error when invalid service data is provided in update' do
        exampleservice
        administrator

        put '/administration/services/update', { 'identifier' => '1234abcd', 'name' => 'Our Web App' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services')
        follow_redirect!
        expect(last_response.body).to contain('Invalid data supplied')
      end

      it 'successfully updates services' do
        exampleservice
        administrator

        current_service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
        expect(current_service['name']).to eq('Our Web App')
        expect(current_service['audience']).to eq('https://service.com')
        expect(current_service['endpoint']).to eq('https://service.com/auth/jwt')
        expect(current_service['secret']).to eq('ykUlP1XMq3RXMd9w')
        !current_service['enabled']

        put '/administration/services/update', { 'identifier' => '1234abcd', 'organisation' => 'Test Org Name', 'name' => 'Our Web App2', 'audience' => 'https://service2.com',
                                                 'endpoint' => 'https://service.com/auth/jwt2', 'secret' => 'ykUlP1XMq3RXMd9w2',
                                                 'enabled' => 'on', 'registrant_name' => 'Dummy User', 'registrant_mail' => 'dummy@example.org' },
            'rack.session' => { subject: @valid_subject }

        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services/1234abcd')

        updated_service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
        expect(updated_service['name']).to eq('Our Web App2')
        expect(updated_service['audience']).to eq('https://service2.com')
        expect(updated_service['endpoint']).to eq('https://service.com/auth/jwt2')
        expect(updated_service['secret']).to eq('ykUlP1XMq3RXMd9w2')
        updated_service['enabled']
      end

      it 'successfully toggles service state' do
        exampleservice
        administrator

        service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
        expect(service['enabled']).to be_falsey

        # Toggle On
        patch '/administration/services/toggle/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services/1234abcd')
        service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
        expect(service['enabled']).to be_truthy

        # Toggle back off
        patch '/administration/services/toggle/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services/1234abcd')
        service = JSON.parse(@redis.hget('serviceproviders', '1234abcd'))
        expect(service['enabled']).to be_falsey
      end

      it 'unknown id sends 404' do
        administrator

        patch '/administration/services/toggle/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'prevents service delete if no identifier' do
        administrator
        delete '/administration/services/delete/xyz', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'deletes a service' do
        exampleservice
        administrator

        expect(@redis.hlen('serviceproviders')).to eq(1)
        delete '/administration/services/delete/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to eq('http://example.org/administration/services')
        expect(@redis.hlen('serviceproviders')).to eq(0)
      end
    end

    describe '/administrators' do
      it 'lists all current administrators' do
        administrator
        get '/administration/administrators', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_ok
        expect(last_response.body).to contain(@valid_subject[:principal])
        expect(last_response.body).to contain('Delete')
      end

      it 'allows administrators to be created' do
        administrator
        get '/administration/administrators/create', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_ok
        expect(last_response.body).to contain('Create Administrator')
      end

      it 'prevents new administrator if no identifier' do
        administrator
        post '/administration/administrators/save', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_ok
        expect(last_response.body).to contain('Invalid form data')
      end

      it 'prevents duplicate administrators from being saved' do
        administrator
        @redis.hset('administrators', 'https://idp.example.com!https://sp.example.com!dummy', { 'name' => 'Dummy User', 'mail' => 'dummy@example.org' }.to_json)

        post '/administration/administrators/save', { 'identifier' => 'https://idp.example.com!https://sp.example.com!dummy' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('http://example.org/administration/administrators')
        follow_redirect!
        expect(last_response.body).to contain('Administrator already exists')
      end

      it 'prevents new administrator if name and mail not supplied' do
        administrator
        post '/administration/administrators/save', { 'identifier' => 'https://idp.example.com!https://sp.example.com!dummy', 'name' => '' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_ok
        expect(last_response.body).to contain('Invalid form data')
      end

      it 'creates new administrator' do
        administrator
        expect(@redis.hlen('administrators')).to eq(1)
        post '/administration/administrators/save', { 'identifier' => 'https://idp.example.com!https://sp.example.com!dummy', 'name' => 'Dummy User', 'mail' => 'dummy@example.org' }, 'rack.session' => { subject: @valid_subject }
        expect(@redis.hlen('administrators')).to eq(2)
        expect(last_response).to be_redirect
        follow_redirect!
        expect(last_response.body).to contain('Administrator added')
      end

      it 'prevents administrator delete if no identifier' do
        administrator
        delete '/administration/administrators/delete', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('http://example.org/administration/administrators')
        follow_redirect!
        expect(last_response.body).to contain('Invalid form data')
      end

      it 'prevents administrator delete if identifier matches current administrator' do
        administrator
        delete '/administration/administrators/delete', { 'identifier' => @valid_subject[:principal] }, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('http://example.org/administration/administrators')
        follow_redirect!
        expect(last_response.body).to contain('Removing your own access is not supported')
      end

      it 'provides an error when no such administrator is requested to be deleted' do
        administrator
        delete '/administration/administrators/delete', { 'identifier' => 'https://idp.example.com!https://sp.example.com!dummy' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('http://example.org/administration/administrators')
        expect(@redis.hlen('administrators')).to eq(1)
        follow_redirect!
        expect(last_response.body).to contain('No such administrator')
      end

      it 'deletes a current administrator' do
        administrator
        @redis.hset('administrators', 'https://idp.example.com!https://sp.example.com!dummy', { 'name' => 'Dummy User', 'mail' => 'dummy@example.org' }.to_json)
        expect(@redis.hlen('administrators')).to eq(2)
        delete '/administration/administrators/delete', { 'identifier' => 'https://idp.example.com!https://sp.example.com!dummy' }, 'rack.session' => { subject: @valid_subject }
        expect(last_response).to be_redirect
        expect(last_response.location).to eq('http://example.org/administration/administrators')
        expect(@redis.hlen('administrators')).to eq(1)
        follow_redirect!
        expect(last_response.body).to contain('Administrator deleted successfully')
      end
    end
  end

  describe '/jwt' do
    it 'directs to login if a jwt url requested when unauthenticated' do
      allow(SecureRandom).to receive(:urlsafe_base64).and_return('1')
      get '/jwt/xyz'
      expect(last_response).to be_redirect
      expect(last_response.location).to eq('http://example.org/login/1')
    end

    describe '/authnrequest/research' do
      it 'sends 404 if no service registered for research JWT' do
        get '/jwt/authnrequest/research/xyz', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'sends 403 if service registered for research JWT is not enabled' do
        exampleservice
        get '/jwt/authnrequest/research/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(403)
      end

      it 'creates a research JWT for active services' do
        enableexampleservice
        get '/jwt/authnrequest/research/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(200)
        expect(last_response.body).to contain('AAF Rapid Connect - Redirection')
        expect(last_response.headers).to include('Set-Cookie')
        expect(last_response.headers['Set-Cookie']).to match(/rack.session=/)
        expect(last_response.headers['Set-Cookie']).to match(/HttpOnly/)
        expect(last_response.headers['Set-Cookie']).not_to match(/expires=/)
      end
    end

    describe '/authnrequest/zendesk' do
      it 'sends 404 if no service registered for zendesk JWT' do
        get '/jwt/authnrequest/zendesk/xyz', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(404)
      end

      it 'sends 403 if service registered for zendesk JWT is not enabled' do
        exampleservice
        get '/jwt/authnrequest/zendesk/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(403)
      end

      it 'shows developer guide' do
        get '/developers'
        expect(last_response).to be_ok
        expect(last_response.body).to contain('Integrating with AAF Rapid Connect')
      end

      it 'creates a zendesk JWT for active services' do
        enableexampleservice
        get '/jwt/authnrequest/zendesk/1234abcd', {}, 'rack.session' => { subject: @valid_subject }
        expect(last_response.status).to eq(302)
        expect(last_response.location).to contain('jwt=')
        expect(last_response.location).to contain('return_to=')
        expect(last_response.headers).to include('Set-Cookie')
        expect(last_response.headers['Set-Cookie']).to match(/rack.session=/)
        expect(last_response.headers['Set-Cookie']).to match(/HttpOnly/)
        expect(last_response.headers['Set-Cookie']).not_to match(/expires=/)
      end
    end
  end

  shared_examples_for 'export API' do
    context 'export disabled' do
      before(:each) do
        Sinatra::Base.set :export, enabled: false
      end

      it '404' do
        get '/export/services'
        expect(last_response.status).to eq 404
      end
    end

    context 'export enabled' do
      before(:each) do
        Sinatra::Base.set :export, enabled: true
      end

      context 'authorize header malformed' do
        it '403 if not supplied' do
          get '/export/services'
          expect(last_response.status).to eq 403
        end

        it '403 if not formed correctly' do
          get '/export/services', 'HTTP_AUTHORIZATION' => 'invalid content'
          expect(last_response.status).to eq 403
        end
      end

      context 'authorize header correctly formed' do
        context 'invalid secret' do
          it '403' do
            get '/export/services', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="wrong_secret"'
            expect(last_response.status).to eq 403
          end
        end
      end
    end
  end

  describe '/export' do
    describe '/services' do
      it_behaves_like 'export API'

      context 'valid request' do
        before(:each) do
          enableexampleservice
        end

        it '200' do
          get '/export/services', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="test_secret"'
          expect(last_response.status).to eq 200
        end

        it 'provides json' do
          get '/export/services', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="test_secret"'
          json = JSON.parse(response.body)
          expect(json['services'][0]['id']).to eq '1234abcd'
          expect(json['services'][0]['rapidconnect']['secret']).to eq 'ykUlP1XMq3RXMd9w'
        end
      end
    end

    describe '/service/:identifier' do
      it_behaves_like 'export API'

      context 'invalid service' do
        it '404' do
          get '/export/services/notvalid', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="test_secret"'
          expect(last_response.status).to eq 404
        end
      end

      context 'valid service' do
        before(:each) do
          enableexampleservice
        end
        it '200' do
          get '/export/service/1234abcd', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="test_secret"'
          expect(last_response.status).to eq 200
        end
        it 'provides json' do
          get '/export/service/1234abcd', nil, 'HTTP_AUTHORIZATION' => 'AAF-RAPID-EXPORT service="test", key="test_secret"'
          json = JSON.parse(response.body)
          expect(json['service']['id']).to eq '1234abcd'
          expect(json['service']['rapidconnect']['secret']).to eq 'ykUlP1XMq3RXMd9w'
        end
      end
    end
  end

  describe '#generate_research_claim' do
    it 'creates a valid claim' do
      rc = RapidConnect.new
      claim = rc.helpers.generate_research_claim('http://service.com', @valid_subject)
      expect(claim[:aud]).to eq('http://service.com')
      expect(claim[:iss]).to eq('https://rapid.example.org')
      expect(claim[:sub]).to eq('https://rapid.example.org!http://service.com!MLD5Q9wrjigVSip53095hAW7Xro=')
      expect(claim[:'https://aaf.edu.au/attributes'][:cn]).to eq(@valid_subject[:cn])
      expect(claim[:'https://aaf.edu.au/attributes'][:mail]).to eq(@valid_subject[:mail])
      expect(claim[:'https://aaf.edu.au/attributes'][:edupersontargetedid]).to eq('https://rapid.example.org!http://service.com!MLD5Q9wrjigVSip53095hAW7Xro=')
      expect(claim[:'https://aaf.edu.au/attributes'][:edupersonprincipalname]).to eq(@valid_subject[:principal_name])
      expect(claim[:'https://aaf.edu.au/attributes'][:edupersonscopedaffiliation]).to eq(@valid_subject[:scoped_affiliation])
    end
  end

  describe '#generate_zendesk_claim' do
    it 'creates a valid claim' do
      rc = RapidConnect.new
      claim = rc.helpers.generate_zendesk_claim('http://service.com', @valid_subject)
      expect(claim[:aud]).to eq('http://service.com')
      expect(claim[:iss]).to eq('https://rapid.example.org')
      expect(claim[:name]).to eq(@valid_subject[:cn])
      expect(claim[:email]).to eq(@valid_subject[:mail])
      expect(claim[:external_id]).to eq('https://rapid.example.org!http://service.com!MLD5Q9wrjigVSip53095hAW7Xro=')
    end
  end

end
