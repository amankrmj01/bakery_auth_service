-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create roles enum type
CREATE TYPE user_role AS ENUM ('USER', 'ADMIN', 'BAKER');

-- Create user status enum type
CREATE TYPE user_status AS ENUM ('ACTIVE', 'INACTIVE', 'LOCKED', 'PENDING_VERIFICATION');

-- Ensure proper permissions
GRANT ALL PRIVILEGES ON DATABASE bakery_auth TO auth_user;
