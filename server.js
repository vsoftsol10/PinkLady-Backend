const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === 'production';

// Validate environment variables FIRST
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error('❌ ERROR: Razorpay credentials not found in environment variables!');
  process.exit(1);
}

// Check if using live keys
const isLiveMode = process.env.RAZORPAY_KEY_ID.startsWith('rzp_live');
if (isProduction && !isLiveMode) {
  console.error('⚠️  WARNING: Running in PRODUCTION but using TEST Razorpay keys!');
}

// CORS configuration
const allowedOrigins = isProduction 
  ? [
      'https://pinklady.thevsoft.com',
      'https://pinkladypaapatchi.com',
      'https://www.pinklady.thevsoft.com',
      'https://www.pinkladypaapatchi.com'
    ]
  : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:5000'];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const normalizedOrigin = origin.replace(/\/$/, '');
    const normalizedAllowed = allowedOrigins.map(o => o.replace(/\/$/, ''));
    
    if (normalizedAllowed.indexOf(normalizedOrigin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`⚠️  CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Razorpay-Signature'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 100 : 1000,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Initialize Razorpay
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Startup logs
console.log(`\n${'='.repeat(60)}`);
console.log(`🚀 SERVER STARTUP - ${new Date().toISOString()}`);
console.log(`${'='.repeat(60)}`);
console.log(`📍 Environment: ${isProduction ? '🔴 PRODUCTION' : '🟡 DEVELOPMENT'}`);
console.log(`🔑 Razorpay Key: ${process.env.RAZORPAY_KEY_ID.substring(0, 20)}...`);
console.log(`💳 Razorpay Mode: ${isLiveMode ? '✅ LIVE' : '⚠️  TEST'}`);
console.log(`🌐 CORS Origins: ${allowedOrigins.join(', ')}`);
console.log(`${'='.repeat(60)}\n`);

// Health check route
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is running",
    mode: isProduction ? 'production' : 'development',
    razorpay_mode: isLiveMode ? 'live' : 'test',
    razorpay_configured: !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET),
    razorpay_key_prefix: process.env.RAZORPAY_KEY_ID.substring(0, 10),
    timestamp: new Date().toISOString()
  });
});

// Create Razorpay Order
app.post("/api/orders/create", async (req, res) => {
  try {
    const { amount, currency, receipt, notes } = req.body;

    console.log('📨 Order Creation Request:', {
      amount,
      currency,
      receipt,
      mode: isLiveMode ? 'LIVE' : 'TEST'
    });

    // Input validation
    if (!amount || !currency || !receipt) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: amount, currency, receipt",
      });
    }

    if (!Number.isInteger(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Amount must be a positive integer in paise",
      });
    }

    const options = {
      amount: amount,
      currency: currency,
      receipt: receipt,
      notes: notes || {},
    };

    console.log(`💰 Creating ${isLiveMode ? 'LIVE' : 'TEST'} order: ${receipt} for ₹${amount / 100}`);
    
    const order = await razorpayInstance.orders.create(options);

    if (!order) {
      return res.status(500).json({
        success: false,
        message: "Error creating Razorpay order",
      });
    }

    console.log(`✅ Order created: ${order.id} [${isLiveMode ? 'LIVE' : 'TEST'} MODE]`);

    res.json({
      success: true,
      order: order,
      key_id: process.env.RAZORPAY_KEY_ID,
      mode: isLiveMode ? 'live' : 'test'
    });
  } catch (err) {
    console.error("❌ Error creating order:", err);
    res.status(500).json({
      success: false,
      message: isProduction ? "Order creation failed" : err.message,
      error: isProduction ? undefined : err.toString()
    });
  }
});

// Verify Payment Signature
app.post("/api/orders/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: "Missing required payment verification fields",
      });
    }

    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    console.log(`🔐 Verifying ${isLiveMode ? 'LIVE' : 'TEST'} payment: ${razorpay_payment_id}`);

    if (razorpay_signature === expectedSign) {
      console.log(`✅ Payment verified: ${razorpay_payment_id} [${isLiveMode ? 'LIVE' : 'TEST'} MODE]`);
      
      res.json({
        success: true,
        message: "Payment verified successfully",
        payment_id: razorpay_payment_id,
        order_id: razorpay_order_id,
        mode: isLiveMode ? 'live' : 'test'
      });
    } else {
      console.error(`❌ Signature mismatch for payment: ${razorpay_payment_id}`);
      
      res.status(400).json({
        success: false,
        message: "Invalid signature - Payment verification failed",
      });
    }
  } catch (err) {
    console.error("❌ Error verifying payment:", err);
    res.status(500).json({
      success: false,
      message: isProduction ? "Verification failed" : err.message,
      error: isProduction ? undefined : err.toString()
    });
  }
});

// Webhook endpoint
app.post("/api/webhook", (req, res) => {
  try {
    const webhookSignature = req.headers['x-razorpay-signature'];
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.warn('⚠️  Webhook secret not configured');
      return res.status(400).json({ error: 'Webhook not configured' });
    }

    const body = JSON.stringify(req.body);
    
    const expectedSignature = crypto
      .createHmac('sha256', webhookSecret)
      .update(body)
      .digest('hex');
    
    if (webhookSignature === expectedSignature) {
      const event = req.body.event;
      const payload = req.body.payload.payment.entity;
      
      console.log(`📨 Webhook: ${event} [${isLiveMode ? 'LIVE' : 'TEST'}]`);
      console.log(`Payment ID: ${payload.id}, Status: ${payload.status}`);
      
      res.json({ status: 'ok' });
    } else {
      console.error('❌ Invalid webhook signature');
      res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (err) {
    console.error('❌ Webhook error:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    message: isProduction ? 'Internal server error' : err.message
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`✅ SERVER RUNNING`);
  console.log(`${'='.repeat(60)}`);
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌍 Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`💳 Razorpay Mode: ${isLiveMode ? '✅ LIVE' : '⚠️  TEST'}`);
  console.log(`\n📋 Available endpoints:`);
  console.log(`  GET  /api/health`);
  console.log(`  POST /api/orders/create`);
  console.log(`  POST /api/orders/verify`);
  console.log(`  POST /api/webhook`);
  console.log(`${'='.repeat(60)}\n`);
});