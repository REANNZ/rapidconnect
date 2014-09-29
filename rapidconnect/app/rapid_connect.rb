require 'sinatra'
require 'sinatra/reloader' if development?
require 'sinatra/config_file'
require 'erubis'
require 'json'
require 'json/jwt'
require 'securerandom'
require 'rack-flash'
require 'redis-rack'
require 'mail'
require 'rdiscount'
require 'json'
require 'uri'

require_relative 'models/rapid_connect_service'

# The RapidConnect application
class RapidConnect < Sinatra::Base
  configure :production, :development do
    use Rack::Session::Redis, expire_in: 3600, secure: Sinatra::Base.production?
  end
  configure :test do
    use Rack::Session::Pool, expire_in: 3600
  end

  use Rack::MethodOverride
  use Rack::Flash, sweep: true

  configure :development do
    register Sinatra::Reloader
  end

  configure :production, :development do
    enable :logging
    register Sinatra::ConfigFile

    set :app_root, File.expand_path(File.join(File.dirname(__FILE__), '..'))
    config_file File.join(settings.app_root, 'config', 'app_config.yml')
    set :app_logfile, File.join(settings.app_root, 'logs', 'app.log')
    set :audit_logfile, File.join(settings.app_root, 'logs', 'audit.log')

    set :erb, escape_html: true

    mail_settings = settings.mail
    Mail.defaults do
      delivery_method :smtp,
                      address: 'localhost',
                      port: '25',
                      user_name: mail_settings[:user_name],
                      password: mail_settings[:password],
                      authentication: :plain,
                      enable_starttls_auto: true
    end

    unless settings.respond_to? :hostname
      set :hostname, ::URI.parse(settings.issuer).hostname
    end
  end

  attr_reader :current_version
  AUTHORIZE_REGEX = /^AAF-RAPID-EXPORT service="([^"]+)", key="([^"]*)?"$/

  def initialize
    super
    check_reopen

    @current_version = '1.0.1'
  end

  def check_reopen
    return if @pid == Process.pid

    @redis = Redis.new

    @app_logger = Logger.new(settings.app_logfile)
    @app_logger.level = Logger::INFO
    @app_logger.formatter = Logger::Formatter.new

    @audit_logger = Logger.new(settings.audit_logfile)
    @audit_logger.level = Logger::INFO

    @pid = Process.pid
  end

  def call(env)
    check_reopen
    super(env)
  end

  ##
  # Marketing Site
  ##
  get '/' do
    erb :welcome, layout: nil
  end

  ###
  # Session Management
  ###
  get '/login/:id' do |id|
    shibboleth_login_url = "/Shibboleth.sso/Login?target=/login/shibboleth/#{id}"
    redirect shibboleth_login_url
  end

  get '/login/shibboleth/:id' do |id|
    # Process Shibboleth provided login details
    if env['HTTP_SHIB_SESSION_ID'] && !env['HTTP_SHIB_SESSION_ID'].empty?
      targets = session[:target] || {}
      target = targets[id.to_s]
      if target
        session[:target].delete id.to_s

        # As we support more attributes in the future the subject should be extended to hold all of them
        subject = {
          principal: env['HTTP_PERSISTENT_ID'],
          cn: env['HTTP_CN'],
          display_name: env['HTTP_DISPLAYNAME'],
          given_name: env['HTTP_GIVENNAME'],
          surname: env['HTTP_SN'],
          mail: env['HTTP_MAIL'],
          principal_name: env['HTTP_EPPN'],
          scoped_affiliation: env['HTTP_AFFILIATION']
        }

        session[:subject] = subject
        @app_logger.info "Established session for #{subject[:cn]}(#{subject[:principal]})"
        redirect target
      else
        redirect '/serviceunknown'
      end
    else
      403
    end
  end

  get '/logout' do
    if session[:subject]
      @app_logger.info "Terminated session for #{session[:subject][:cn]}(#{session[:subject][:principal]})"
    end
    session.clear
    redirect '/'
  end

  get '/serviceunknown' do
    erb :serviceunknown
  end

  ###
  # Service Registration
  ###
  before '/registration*' do
    authenticated?
  end

  get '/registration' do
    @organisations = load_organisations
    erb :'registration/index'
  end

  def load_service(identifier)
    json = @redis.hget('serviceproviders', identifier)
    return nil if json.nil?

    RapidConnectService.new.from_json(json).tap do |service|
      service.identifier = identifier
    end
  end

  def load_all_services
    @redis.hgetall('serviceproviders').sort.reduce({}) do |hash, (id, json)|
      service = RapidConnectService.new.from_json(json).tap do |s|
        s.identifier = id
      end
      hash.merge(id => service)
    end
  end

  def service_attrs
    %i(organisation name audience endpoint secret).reduce({}) do |map, sym|
      map.merge(sym => params[sym])
    end
  end

  def registrant_attrs
    subject = session[:subject]
    return {} if subject.nil?
    { registrant_name: subject[:cn], registrant_mail: subject[:mail] }
  end

  def admin_supplied_attrs
    base = { enabled: !params[:enabled].nil? }

    %i(registrant_name registrant_mail).reduce(base) do |map, sym|
      map.merge(sym => params[sym])
    end
  end

  post '/registration/save' do
    service = RapidConnectService.new
    service.attributes = service_attrs.merge(registrant_attrs)

    if service.valid?
      identifier = service.identifier!
      if @redis.hexists('serviceproviders', identifier)
        @organisations = load_organisations
        flash[:error] = 'Invalid identifier generated. Please re-submit registration.'
        erb :'registration/index'
      else
        service.enabled = (settings.federation == 'test')
        @redis.hset('serviceproviders', identifier, service.to_json)

        if service.enabled
          session[:registration_identifier] = identifier
        else
          send_registration_email(service)
        end

        @app_logger.info "New service #{service}, endpoint: #{service.endpoint}, contact email: #{service.registrant_mail}, organisation: #{service.organisation}"
        redirect to('/registration/complete')
      end
    else
      @organisations = load_organisations
      flash[:error] = "Invalid data supplied: #{service.errors.full_messages.join("\n")}"
      erb :'registration/index'
    end
  end

  get '/registration/complete' do
    @identifier = nil
    if settings.federation == 'test'
      @identifier = session[:registration_identifier]
    end
    erb :'registration/complete'
  end

  ###
  # Administration
  ###
  before '/administration*' do
    authenticated?
    administrator?
  end

  get '/administration' do
    erb :'administration/index'
  end

  # Administration - Services
  get '/administration/services' do
    @services = load_all_services
    erb :'administration/services/list'
  end

  get '/administration/services/:identifier' do |identifier|
    @identifier = identifier
    @service = load_service(identifier)
    halt 404 if @service.nil?

    erb :'administration/services/show'
  end

  get '/administration/services/edit/:identifier' do |identifier|
    @identifier = identifier
    @service = load_service(identifier)
    halt 404 if @service.nil?

    @organisations = load_organisations
    erb :'administration/services/edit'
  end

  put '/administration/services/update' do
    identifier = params[:identifier]
    service = load_service(identifier)

    if service.nil?
      flash[:error] = 'Invalid data supplied'
      halt redirect to('/administration/services')
    end

    service.attributes = service_attrs.merge(admin_supplied_attrs)

    if service.valid?
      @redis.hset('serviceproviders', identifier, service.to_json)
      @app_logger.info "Service #{identifier} updated by #{session[:subject][:principal]} #{session[:subject][:cn]}"
      redirect to('/administration/services/' + identifier)
    else
      flash[:error] = 'Invalid data supplied'
      redirect to('/administration/services')
    end
  end

  patch '/administration/services/toggle/:identifier' do |identifier|
    service = load_service(identifier)
    halt 404 if service.nil?

    service.enabled = !service.enabled

    @redis.hset('serviceproviders', identifier, service.to_json)
    @app_logger.info "Service #{identifier} toggled by #{session[:subject][:principal]} #{session[:subject][:cn]}"

    flash[:success] = 'Service modified successfully'
    redirect to('/administration/services/' + identifier)
  end

  delete '/administration/services/delete/:identifier' do |identifier|
    service = load_service(identifier)
    halt 404 if service.nil?

    @redis.hdel('serviceproviders', identifier)
    @app_logger.info "Service #{identifier} deleted by #{session[:subject][:principal]} #{session[:subject][:cn]}"
    flash[:success] = 'Service deleted successfully'
    redirect '/administration/services'
  end

  # Administration - Administrators
  get '/administration/administrators' do
    administrators_raw = @redis.hgetall('administrators')
    @administrators = administrators_raw.reduce({}) { |map, (k, v)| map.merge(k => JSON.parse(v)) }
    erb :'administration/administrators/list'
  end

  get '/administration/administrators/create' do
    erb :'administration/administrators/create'
  end

  post '/administration/administrators/save' do
    identifier = params[:identifier]
    if !identifier || identifier.empty?
      flash[:error] = 'Invalid form data'
      erb :'administration/administrators/create'
    else
      if @redis.hexists('administrators', identifier)
        flash[:error] = 'Administrator already exists'
        redirect '/administration/administrators'
      else
        name = params[:name]
        mail = params[:mail]

        if name && !name.empty? && mail && !mail.empty?
          @redis.hset('administrators', identifier, { 'name' => name, 'mail' => mail }.to_json)
          @app_logger.info "Current administrator #{session[:subject][:principal]} #{session[:subject][:cn]} added new administrator #{name}, #{mail}"
          flash[:success] = 'Administrator added'
          redirect '/administration/administrators'
        else
          flash[:error] = 'Invalid form data'
          erb :'administration/administrators/create'
        end
      end
    end
  end

  delete '/administration/administrators/delete' do
    identifier = params[:identifier]
    if !identifier || identifier.empty?
      flash[:error] = 'Invalid form data'
    else
      if identifier == session[:subject][:principal]
        flash[:error] = 'Removing your own access is not supported'
      else
        if @redis.hexists('administrators', identifier)
          @redis.hdel('administrators', identifier)
          @app_logger.info "Current administrator #{session[:subject][:principal]} #{session[:subject][:cn]} deleted administrator #{identifier}"
          flash[:success] = 'Administrator deleted successfully'
        else
          flash[:error] = 'No such administrator'
        end
      end
    end
    redirect '/administration/administrators'
  end

  ###
  # JWT
  ###
  before '/jwt/*' do
    authenticated?
  end

  get '/jwt/authnrequest/research/:identifier' do |identifier|
    service = load_service(identifier)
    if service.nil?
      halt 404, 'There is no such endpoint defined please validate the request.'
    end

    if service.enabled
      subject = session['subject']
      claim = generate_research_claim(service.audience, subject)
      @jws = JSON::JWT.new(claim).sign(service.secret)
      @endpoint = service.endpoint

      # To enable raptor and other tools to report on RC like we would any other
      # IdP we create a shibboleth styled audit.log file for each service access.
      # Format:
      # auditEventTime|requestBinding|requestId|relyingPartyId|messageProfileId|assertingPartyId|responseBinding|responseId|principalName|authNMethod|releasedAttributeId1,releasedAttributeId2,|nameIdentifier|assertion1ID,assertion2ID,|
      @audit_logger.info "#{Time.now.utc.strftime '%Y%m%dT%H%M%SZ'}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:research:get|#{identifier}|#{claim[:aud]}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:jwt:research:sso|#{claim[:iss]}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:jwt:research:post|#{claim[:jti]}|#{subject[:principal]}|urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig|cn,mail,displayname,givenname,surname,edupersontargetedid,edupersonscopedaffiliation,edupersonprincipalname|||"
      @app_logger.info "Provided details for #{session[:subject][:cn]}(#{session[:subject][:mail]}) to service #{service.name}(#{service.endpoint})"
      @app_logger.debug "#{claim}"

      erb :post, layout: :post
    else
      halt 403, "The service \"#{service.name}\" is unable to process requests at this time."
    end
  end

  get '/jwt/authnrequest/zendesk/:identifier' do |identifier|
    service = load_service(identifier)
    if service.nil?
      halt 404, 'There is no such zendesk endpoint defined please validate the request.'
    end

    if service.enabled
      subject = session['subject']
      claim = generate_zendesk_claim(service.audience, subject)
      jws = JSON::JWT.new(claim).sign(service.secret)
      endpoint = service.endpoint

      # To enable raptor and other tools to report on rapid like we would any other
      # IdP we create a shibboleth styled audit.log file for each service access.
      # Format:
      # auditEventTime|requestBinding|requestId|relyingPartyId|messageProfileId|assertingPartyId|responseBinding|responseId|principalName|authNMethod|releasedAttributeId1,releasedAttributeId2,|nameIdentifier|assertion1ID,assertion2ID,|
      @audit_logger.info "#{Time.now.utc.strftime '%Y%m%dT%H%M%SZ'}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:zendesk:get|#{identifier}|#{claim[:aud]}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:jwt:zendesk:sso|#{claim[:iss]}|urn:mace:aaf.edu.au:rapid.aaf.edu.au:jwt:zendesk:post|#{claim[:jti]}|#{subject[:principal]}|urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig|cn,mail,edupersontargetedid,o|||"
      @app_logger.info "Provided details for #{session[:subject][:cn]}(#{session[:subject][:mail]}) to Zendesk"

      redirect "#{endpoint}?jwt=#{jws}&return_to=#{params[:return_to]}"
    else
      halt 403, "The zendesk service \"#{service.name}\" is unable to process requests at this time."
    end
  end

  get '/developers' do
    erb :developers, locals: { text: markdown(:'documentation/developers') }
  end

  def flash_types
    [:success, :warning, :error]
  end

  def authenticated?
    return if session[:subject]

    id = SecureRandom.urlsafe_base64(24, false)
    session[:target] ||= {}
    session[:target][id] = request.url
    redirect "/login/#{id}"
  end

  def administrator?
    return if @redis.hexists('administrators', session[:subject][:principal])

    @app_logger.warn "Denied access to administrative area to #{session[:subject][:principal]} #{session[:subject][:cn]}"
    status 403
    halt erb :'administration/administrators/denied'
  end

  def generate_research_claim(audience, subject)
    response_time = Time.now
    principal = repack_principal(subject, settings.issuer, audience)

    # Research JWT authnresponses support the following attributes
    # eduPersonTargetedID [pseudonymous identifier and JWT subject identifier]
    # cn, givenName(optional), surname(optional), mail [personal identifiers]
    # eduPersonScopedAffiliation [affiliation identifier]
    # eppn (optional) [subject identifier]
    {
      iss: settings.issuer,
      iat: response_time,
      jti: SecureRandom.urlsafe_base64(24, false),
      nbf: 1.minute.ago,
      exp: 2.minute.from_now,
      typ: 'authnresponse',
      aud: audience,
      sub: principal,
      :'https://aaf.edu.au/attributes' => {
        cn: subject[:cn],
        mail: subject[:mail],
        displayname: subject[:display_name],
        givenname: subject[:given_name],
        surname: subject[:surname],
        edupersontargetedid: principal,
        edupersonscopedaffiliation: subject[:scoped_affiliation],
        edupersonprincipalname: subject[:principal_name]
      }
    }
  end

  # Generate tokens specifically for Zendesk instances which define their own format
  def generate_zendesk_claim(audience, subject)
    response_time = Time.now

    { iss: settings.issuer,
      iat: response_time,
      jti: SecureRandom.urlsafe_base64(24, false),
      nbf: 1.minute.ago,
      exp: 2.minute.from_now,
      typ: 'authnresponse',
      aud: audience,
      name: subject[:cn],
      email: subject[:mail],
      external_id: repack_principal(subject, settings.issuer, audience),
      organization: subject[:o]
    }
  end

  # Refine EPTID for each rapid connect service this user visits
  #
  # The eduPersonTargetedID value is an opaque string of no more than 256 characters
  # The format comprises the entity name of the identity provider, the entity name of the service provider, and the opaque string value. These strings are separated by a bang
  def repack_principal(subject, issuer, audience)
    parts = subject[:principal].split('!')
    new_opaque = OpenSSL::Digest::SHA1.base64digest "#{parts[2]} #{subject[:mail]} #{audience}"
    new_principal = "#{issuer}!#{audience}!#{new_opaque}"
    @app_logger.info "Translated incoming principal #{subject[:principal]} (#{subject[:cn]}, #{subject[:mail]}) to #{new_principal} for aud #{audience}"

    new_principal
  end

  ##
  # New Service Registration Notification
  ##
  def send_registration_email(service)
    mail_settings = settings.mail
    settings_hostname = settings.hostname
    Mail.deliver do
      from mail_settings[:from]
      to mail_settings[:to]
      subject 'New service registration for AAF Rapid Connect'
      html_part do
        content_type 'text/html; charset=UTF-8'
        body "
          There is a new registration within AAF Rapid Connect that needs to be enabled.
          <br><br>
          <strong>Details</strong>
          <br>
          <ul>
            <li>Service Name: #{service.name}</li>
            <li>Endpoint: #{service.endpoint}</li>
            <li>Creator: #{service.registrant_name} (#{service.registrant_mail})</li>
          </ul>
          <br><br>
          Please ensure <strong>all endpoints utilise HTTPS</strong> before enabling.
          <br><br>
          For more information and to enable this service please view the <a href='https://#{settings_hostname}/administration/services/#{service.identifier}'>full service record</a> in AAF Rapid Connect.
        "
      end
    end
  end

  ##
  # Export Data
  ##
  before '/export*' do
    api_authenticated?
  end

  get '/export/service/:identifier' do |identifier|
    content_type :json

    service = load_service(identifier)
    halt 404 if service.nil?

    { service: service_as_json(identifier, service) }.to_json
  end

  get '/export/services' do
    content_type :json

    services = load_all_services.sort.map do |(id, service)|
      service_as_json(id, service)
    end

    { services: services }.to_json
  end

  def service_as_json(id, service)
    { id: id,
      name: service.name,
      contact: {
        name: service.registrant_name,
        email: service.registrant_mail,
        type: 'technical'
      },
      rapidconnect: {
        audience: service.audience,
        callback: service.endpoint,
        secret: service.secret,
        endpoints: {
          scholarly: "https://#{settings.hostname}/jwt/authnrequest/research/#{id}"
        }
      },
      enabled: service.enabled,
      organization: service.organisation }
  end

  def api_authenticated?
    if settings.export[:enabled]
      authorization = request.env['HTTP_AUTHORIZATION']
      unless authorization && authorization =~ AUTHORIZE_REGEX
        halt 403, 'Invalid authorization token'
      end

      service, secret = authorization.match(AUTHORIZE_REGEX).captures
      unless secret == settings.export[:secret]
        halt 403, 'Invalid authorization header'
      end

      @app_logger.info "Established API session for service #{service}"
    else
      halt 404
    end
  end

  ##
  # Organisation names via FR
  ##
  def load_organisations
    JSON.parse(IO.read(settings.organisations))
  end
end
