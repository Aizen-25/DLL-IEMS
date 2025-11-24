require 'active_record'

class AllowNullSerialNumber < ActiveRecord::Migration[7.0]
  def up
    # SQLite doesn't support altering column nullability directly; recreate table without NOT NULL on serial_number
    if ActiveRecord::Base.connection.adapter_name == 'SQLite'
      say "Recreating equipments table to allow NULL serial_number (SQLite)"
      ActiveRecord::Base.transaction do
        execute <<-SQL
          CREATE TABLE equipments_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            serial_number TEXT,
            model TEXT,
            vendor TEXT,
            purchase_date DATE,
            warranty_until DATE,
            status TEXT,
            location TEXT,
            category TEXT,
            notes TEXT,
            quantity INTEGER,
            purchase_price DECIMAL,
            created_at DATETIME,
            updated_at DATETIME
          );
        SQL

        execute <<-SQL
          INSERT INTO equipments_new (id, name, serial_number, model, vendor, purchase_date, warranty_until, status, location, category, notes, quantity, purchase_price, created_at, updated_at)
          SELECT id, name, serial_number, model, vendor, purchase_date, warranty_until, status, location, category, notes, quantity, purchase_price, created_at, updated_at FROM equipments;
        SQL

        execute "DROP TABLE equipments;"
        execute "ALTER TABLE equipments_new RENAME TO equipments;"
        # recreate unique index on serial_number (allows multiple NULLs)
        execute "CREATE UNIQUE INDEX IF NOT EXISTS index_equipments_on_serial_number ON equipments(serial_number);"
      end
    else
      change_column_null :equipments, :serial_number, true
    end
  end

  def down
    # revert: make serial_number NOT NULL (skip if SQLite and NULL values exist)
    if ActiveRecord::Base.connection.adapter_name == 'SQLite'
      say "Recreating equipments table to make serial_number NOT NULL (SQLite)"
      ActiveRecord::Base.transaction do
        execute <<-SQL
          CREATE TABLE equipments_old (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            serial_number TEXT NOT NULL,
            model TEXT,
            vendor TEXT,
            purchase_date DATE,
            warranty_until DATE,
            status TEXT,
            location TEXT,
            category TEXT,
            notes TEXT,
            quantity INTEGER,
            purchase_price DECIMAL,
            created_at DATETIME,
            updated_at DATETIME
          );
        SQL

        # For rows with NULL serial_number, set a placeholder to avoid constraint error
        execute <<-SQL
          INSERT INTO equipments_old (id, name, serial_number, model, vendor, purchase_date, warranty_until, status, location, category, notes, quantity, purchase_price, created_at, updated_at)
          SELECT id, name, COALESCE(serial_number, ('SEQ-' || id)), model, vendor, purchase_date, warranty_until, status, location, category, notes, quantity, purchase_price, created_at, updated_at FROM equipments;
        SQL

        execute "DROP TABLE equipments;"
        execute "ALTER TABLE equipments_old RENAME TO equipments;"
        execute "CREATE UNIQUE INDEX IF NOT EXISTS index_equipments_on_serial_number ON equipments(serial_number);"
      end
    else
      change_column_null :equipments, :serial_number, false
    end
  end
end
