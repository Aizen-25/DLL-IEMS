class AddTemporaryPasswordToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :temporary_password, :string, null: true
  end
end
