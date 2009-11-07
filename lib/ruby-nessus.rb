# Includes
$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
# Dependencies
require 'rubygems'
require 'nokogiri'
require 'chronic'
# Ruby-Nessus Files
require 'ruby-nessus/nessus'
require 'ruby-nessus/version'