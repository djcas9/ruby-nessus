require 'rubygems'
require 'nokogiri'
require 'chronic'
$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'ruby-nessus/nessus'
require 'ruby-nessus/version'