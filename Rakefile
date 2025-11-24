require 'sinatra/activerecord/rake'
require_relative 'app'

# Load custom rake tasks from lib/tasks
Dir.glob(File.join(File.dirname(__FILE__), 'lib', 'tasks', '**', '*.rake')).each do |r|
	import r
end
