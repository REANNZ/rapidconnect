# Instructions for setting up a Rapid Connect server

This is an initial cut of the document and doesn't go into fine depth on things like Apache and Shibboleth SP. We'll review this in the future if necessary. We also assume the deployer is comfortable with things like rbenv, bundler and unicorn. If not there is a lot of great doco available on these topics on the web.

**Authors**: Bradley Beddoes and Shaun Mangelsdorf

## System

### Install

* Base CentOS image
* Apache HTTPD
* Shibboleth SP
* Redis 2.6+
* Git 1.7+

### Configuration

1. Create user 'rapid'
1. Ensure redis uses AOF persistence and appendonly
1. Run 'redis-cli bgrewriteaof' daily
1. Configure Shibboleth SP against required AAF environment. Ensure correct attributes by using the supplied attribute-map.xml locally and to select attributes from FR to be provided by federation IdP.
1. Configure HTTPD using supplied rapidconnect.conf

### As user 'rapid'

#### Install
RBenv
Ruby 2+
Bundlder

#### Project setup
Clone from github to ~/rapidconnect and change to this directory. AAF deployments should come from [https://github.com/ausaccessfed/rapidconnect](https://github.com/ausaccessfed/rapidconnect). Should Rapid Connect be deployed by non AAF we suggest your fork the project and deploy from there.

##### FR Organisations
2. change to frdatacollator directory
1. Copy config.yml.dist to config.yml, setup appropriately
2. Run $> bundle install
1. Have cron run 'bundle exec ruby collator.rb' daily

		@hourly bundle exec ruby /home/rapid/rapidconnect/frdatacollator/collator.rb
2. By default this outputs the file /tmp/fr_org_names.json which is used by the Rapid Connect Sinatra configuration

#### RC Setup
2. change to rapidconnect directory
3. copy config/app_config.yml.dist to app_config.yml, setup appropriately. The value for *federation* MUST be 'test' or 'production'
4. copy config/unicorn.rb.dist to config/unicorn.rb
5. create the directory structure /opt/rapidconnect and switch to that directory
6. symlink /home/rapid/rapidconnect/rapidconnect to application
7. create the directory pki and setup your HTTP SSL keys as defined in the example apache configuration
8. copy the rapidconnect logrotate example to /etc/logrotate.d/logrotate
9. copy the rapidconnect init.d script to /etc/init.d
10. ensure httpd, redis and rapidconnect are started in appropriate runlevels
11. start the rapidconnect service

Should Rapid Connect ever be deployed by non AAF users the marketing page and developer documentation will need to be ammended in your fork.

## Web App

#### Administration rights
Access your rapid connect servers administration url [https://rapid.example.edu.au/administration](https://rapid.example.edu.au/administration).

You will be denied access but your EPTID will be provided. Copy this then switch to a shell session.

Use redis-cli set first administrator:

	$> redis-cli
	redis 127.0.0.1:6379> hset administrators <EPTID> "{\"name\":\"Common Name\",\"mail\":\"emailaddress@example.edu.au\"}"

Refresh the original administration URL and you should have access rights. In the future new administrators can be assigned using the web UI.
