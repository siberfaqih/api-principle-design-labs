INSERT INTO users (name, plan, api_key) VALUES
  ('Alice', 'free', '11111111-1111-1111-1111-111111111111'),
  ('Bob',   'pro',  '22222222-2222-2222-2222-222222222222')
ON CONFLICT DO NOTHING;

INSERT INTO items (name, price) VALUES
  ('Keyboard', 399000.00),
  ('Mouse', 199000.00),
  ('Monitor', 1999000.00),
  ('USB-C Cable', 99000.00),
  ('Laptop Stand', 249000.00),
  ('Headset', 899000.00),
  ('Webcam', 549000.00),
  ('SSD 1TB', 1499000.00),
  ('Power Bank', 299000.00),
  ('Smartphone', 3999000.00)
ON CONFLICT DO NOTHING;