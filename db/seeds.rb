require_relative '../models/equipment'

# Use idempotent seeding to avoid unique constraint errors on serial_number.
seed_items = [
  { name: 'Dell Latitude 7420', serial_number: 'DL7420-001', model: 'Latitude 7420', vendor: 'Dell', purchase_date: '2022-03-15', warranty_until: '2025-03-14', status: 'deployed', location: 'Office A - Desk 12', category: 'Laptop', notes: 'Assigned to Alice', quantity: 1, purchase_price: 1800.00 },
  { name: 'Cisco Switch 2960', serial_number: 'CS2960-1234', model: '2960-X', vendor: 'Cisco', purchase_date: '2020-07-22', warranty_until: '2023-07-21', status: 'available', location: 'Server Room', category: 'Network', notes: '', quantity: 5, purchase_price: 400.00 },
  { name: 'HP ProDesk 600', serial_number: 'HP600-5678', model: 'ProDesk 600 G5', vendor: 'HP', purchase_date: '2021-11-01', warranty_until: '2024-11-01', status: 'maintenance', location: 'IT Workshop', category: 'Desktop', notes: 'Needs SSD replacement', quantity: 2, purchase_price: 750.00 }
]

seed_items.each do |attrs|
  item = Equipment.find_or_initialize_by(serial_number: attrs[:serial_number])
  # assign or update attributes (except serial_number since it's the key)
  item.assign_attributes(attrs)
  item.save!
end

puts "Seeded/upserted #{Equipment.count} equipments"

# Add a sample pending request if none exists
if defined?(Request) && Request.count == 0
  r = Request.new(
    equipment_id: Equipment.first&.id,
    quantity: 1,
    requester_name: 'John Doe',
    requested_at: Time.now,
    status: 'pending'
  )
  r.save!
  puts "Created sample request"
end
