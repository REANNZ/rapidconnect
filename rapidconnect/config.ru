require 'rubygems'
require 'bundler'
require 'sinatra'
require './app/rapid_connect'

Bundler.require

run RapidConnect
