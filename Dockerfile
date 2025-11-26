FROM ruby:3.1

RUN apt-get update && apt-get install -y \
  build-essential \
  libpq-dev \
  git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install gems (copy Gemfiles first for better caching)
COPY Gemfile Gemfile.lock* ./
RUN gem install bundler && bundle install --jobs 4 --retry 3

# Copy application
COPY . .

# Make entrypoint executable
RUN chmod +x ./entrypoint.sh

EXPOSE 4567

CMD ["./entrypoint.sh"]
