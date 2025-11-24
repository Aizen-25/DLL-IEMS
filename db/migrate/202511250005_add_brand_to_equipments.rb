class AddBrandToEquipments < ActiveRecord::Migration[7.0]
  def change
    add_column :equipments, :brand, :string
  end
end
