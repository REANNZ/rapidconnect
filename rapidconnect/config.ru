require 'rubygems'
require 'bundler'
require 'sinatra'

Bundler.require

require './app/rapid_connect'

run RapidConnect
