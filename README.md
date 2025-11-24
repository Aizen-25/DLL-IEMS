# IT Equipment Inventory (Sinatra)

Simple IT Equipment inventory management app built with Sinatra + ActiveRecord + SQLite.

Prerequisites
- Ruby (3.0+)
- Bundler (`gem install bundler`)

Setup (PowerShell)
```powershell
cd "d:\Master of Information Technology\WITM\Demo\Inventory management"
bundle install
# migrate and seed DB
bundle exec rake db:migrate
bundle exec rake db:seed
# run the app
bundle exec rackup -p 4567
```

Then open http://localhost:4567 in your browser.

API endpoints
- `GET /api/equipments` - list JSON
- `GET /api/equipments/:id` - single equipment JSON

Next steps
- Add authentication
- Add pagination and search
- Add export (CSV) and import features
