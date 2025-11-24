namespace :db do
  desc "Clear all application data (equipments, requests, activities). Prompts for confirmation before running."
  task :clear_all => :environment do
    puts "WARNING: This will permanently delete all records from equipments, requests, and activities."
    print "Type 'YES' to proceed: "
    confirm = STDIN.gets.to_s.chomp
    unless confirm == 'YES'
      puts "Aborted. No changes made."
      next
    end

    models = []
    begin
      models = [Object.const_get('Activity'), Object.const_get('Request'), Object.const_get('Equipment')]
    rescue NameError => e
      puts "Model load error: #{e.message}"
    end

    ActiveRecord::Base.transaction do
      models.each do |m|
        begin
          puts "Deleting #{m.name}..."
          m.delete_all
        rescue => ex
          puts "Failed to clear #{m}: #{ex.message}"
        end
      end

      # Reset sqlite sequences if using SQLite
      if ActiveRecord::Base.connection.adapter_name.downcase.include?('sqlite')
        %w[equipments requests activities].each do |t|
          begin
            ActiveRecord::Base.connection.execute("DELETE FROM sqlite_sequence WHERE name='#{t}'")
          rescue => _e
          end
        end
      elsif ActiveRecord::Base.connection.adapter_name.downcase.include?('postgres')
        # reset sequences for Postgres
        ActiveRecord::Base.connection.tables.each do |t|
          next if t == 'schema_migrations'
          begin
            ActiveRecord::Base.connection.reset_pk_sequence!(t)
          rescue => _e
          end
        end
      end
    end

    puts "All selected data cleared."
  end
end
