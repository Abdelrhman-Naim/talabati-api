const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

// Middleware
app.use(cors());
app.use(express.json());

// In-memory mock database for Talabati API
let orders = [
  { id: 1, customer: "Ahmad", item: "Chicken Shawarma Meal", price: 15.5, status: "Delivered" },
  { id: 2, customer: "Sara", item: "Margherita Pizza (Large)", price: 28.0, status: "Preparing" },
  { id: 3, customer: "Omar", item: "Beef Burger with Fries", price: 22.0, status: "Out for Delivery" }
];

const restaurants = [
  { id: 1, name: "Al-Quds Grill", cuisine: "Middle Eastern", rating: 4.8 },
  { id: 2, name: "Napoli Express", cuisine: "Italian", rating: 4.6 },
  { id: 3, name: "Burger Station", cuisine: "Fast Food", rating: 4.5 }
];

// 1. Root Route (Health & Welcome)
app.get('/', (req, res) => {
  res.json({
    status: "success",
    service: "Talabati API",
    platform: "Taqat Academy",
    message: "Talabati API is running successfully in Docker container!",
    timestamp: new Date().toISOString(),
    endpoints: {
      health: "/health",
      orders: "/api/orders",
      restaurants: "/api/restaurants"
    }
  });
});

// 2. Health check route for container orchestrators
app.get('/health', (req, res) => {
  res.status(200).json({
    status: "healthy",
    uptime: `${Math.floor(process.uptime())} seconds`,
    timestamp: new Date().toISOString()
  });
});

// 3. Orders Routes
app.get('/api/orders', (req, res) => {
  res.json({
    count: orders.length,
    orders: orders
  });
});

app.get('/api/orders/:id', (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const order = orders.find(o => o.id === orderId);
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }
  res.json(order);
});

app.post('/api/orders', (req, res) => {
  const { customer, item, price } = req.body;
  if (!customer || !item) {
    return res.status(400).json({ error: "Customer name and item are required" });
  }
  const newOrder = {
    id: orders.length > 0 ? Math.max(...orders.map(o => o.id)) + 1 : 1,
    customer,
    item,
    price: price || 0,
    status: "Received",
    createdAt: new Date().toISOString()
  };
  orders.push(newOrder);
  res.status(201).json({
    message: "Order placed successfully",
    order: newOrder
  });
});

// 4. Restaurants Route
app.get('/api/restaurants', (req, res) => {
  res.json({
    count: restaurants.length,
    restaurants: restaurants
  });
});

// 5. 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Start Server
const server = app.listen(PORT, HOST, () => {
  console.log(`[Talabati API] Server listening on http://${HOST}:${PORT}`);
  console.log(`[Talabati API] Environment: ${process.env.NODE_ENV || 'production'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});
