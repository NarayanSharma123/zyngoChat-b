const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const socketIo = require("socket.io");
const http = require("http");
const { timestamp } = require("console");

require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const onlineUsers = {};

io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  socket.on("join", async (userId) => {
    socket.userId = userId;
    socket.join(userId);

    await User.findByIdAndUpdate(userId, { isOnline: true, lastSeen: null });
    onlineUsers[userId] = socket.id;

    // const allStatuses = await User.find({}, "_id isOnline lastSeen").lean();
    io.emit("user_status", { userId, isOnline: true, lastSeen: null });
    Object.keys(onlineUsers).forEach((id) => {
      io.to(socket.id).emit("user_status", {
        userId: id,
        isOnline: true,
        lastSeen: null,
      });
    });
  });

  socket.on("send_message", async (data) => {
    console.log("Message received:", data);

    const { senderId, receiverId, message } = data;

    try {
      const newMessage = new Messages({
        receiverId,
        senderId,
        message,
        timestamp: new Date(),
      });

      await newMessage.save();

      io.to(receiverId).emit("receive_message", {
        senderId,
        message,
        timestamp: newMessage.timestamp,
      });
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });

  socket.on("disconnect", async () => {
    console.log("A user disconnected:", socket.id);

    if (socket.userId) {
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: false,
        lastSeen: new Date(),
      });
      delete onlineUsers[socket.userId];

      io.emit("user_status", {
        userId: socket.userId,
        isOnline: false,
        lastSeen: new Date().toISOString(),
      });
    }
  });
});

app.use(
  cors({
    origin: ["http://localhost:3000", process.env.CLIENT_URL],
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "ZyngoUsers",
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});
const upload = multer({ storage });

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, "First name is required"],
    trim: true,
  },
  lastName: {
    type: String,
    required: [true, "Last name is required"],
    trim: true,
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  profileImage: String,
  about: { type: String, default: "" },
  phone: { type: String, default: "" },
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date, default: null },
});

const User = mongoose.model("User", UserSchema);

const MessageSchema = new mongoose.Schema({
  senderId: String,
  receiverId: String,
  message: String,
  imageUrl: {
    type: String,
    default: null,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});
const Messages = mongoose.model("Message", MessageSchema);

// Token Verify Middleware
function verifyAccessToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Access token missing" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

// Refresh Token Route
app.post("/api/refresh-token", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token missing" });
  }

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_TOKEN_SECRET
    );
    const newAccessToken = jwt.sign(
      { id: decoded.id, email: decoded.email },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: "Invalid refresh token" });
  }
});

app.get("/api/profile", verifyAccessToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Profile Update Route
app.put("/api/update-profile", verifyAccessToken, async (req, res) => {
  try {
    const updates = {};
    const allowedFields = ["firstName", "lastName", "about", "phone"];

    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true }
    ).select("-password");

    if (!updatedUser) return res.status(404).json({ error: "User not found" });

    res.status(200).json({ message: "Profile updated", user: updatedUser });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Profile Image Update Route
app.put(
  "/api/update-profile-image",
  verifyAccessToken,
  upload.single("profileImage"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No image file uploaded" });
      }

      const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        { $set: { profileImage: req.file.path } }, // Cloudinary ka URL
        { new: true }
      ).select("-password");

      res
        .status(200)
        .json({ message: "Profile image updated", user: updatedUser });
    } catch (err) {
      console.error("Profile image update error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// signup route
app.post("/api/signup", upload.single("profileImage"), async (req, res) => {
  try {
    console.log("REQ BODY:", req.body);
    console.log("REQ FILE:", req.file);

    const { firstName, lastName, email, password } = req.body;

    if (
      !firstName?.trim() ||
      !lastName?.trim() ||
      !email?.trim() ||
      !password?.trim()
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }
    const profileImage = req.file?.path || req.body.profileImage;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      profileImage,
    });
    await user.save();
    res.status(201).json({ message: "User registered", user });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login Request Body:", req.body);
    const existingUser = await User.findOne({ email });
    if (!existingUser) return res.status(400).json({ error: "User not found" });

    const isPasswordMatch = await bcrypt.compare(
      password,
      existingUser.password
    );
    if (!isPasswordMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const accessToken = jwt.sign(
      { id: existingUser._id, email: existingUser.email },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { id: existingUser._id, email: existingUser.email },
      process.env.JWT_REFRESH_TOKEN_SECRET,
      { expiresIn: "30d" }
    );

    // Set HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      user: {
        _id: existingUser._id,
        firstName: existingUser.firstName,
        lastName: existingUser.lastName,
        email: existingUser.email,
        profileImage: existingUser.profileImage,
      },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/chat/contacts/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    await User.exists({ _id: userId });
    const currentUser = await User.findById(userId);

    const contacts = await User.find(
      { _id: { $ne: userId } },
      { firstName: 1, lastName: 1, profileImage: 1, isOnline: 1, lastSeen: 1 }
    ).lean();

    res.status(200).json({ contacts });
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Server error fetching contacts" });
  }
});

app.get("/chat/status/:userId", async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select(
      "isOnline lastSeen"
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    res.status(200).json({
      isOnline: user.isOnline,
      lastSeen: user.lastSeen,
    });
  } catch (err) {
    console.error("Error fetching status:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/chat/messages/:senderId/:receiverId", async (req, res) => {
  const { senderId, receiverId } = req.params;

  try {
    const messages = await Messages.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId },
      ],
    }).sort({ timestamp: 1 }); // ascending order

    res.status(200).json({ messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// image chat send route
app.post("/chat/send-image", upload.single("image"), async (req, res) => {
  try {
    const { senderId, receiverId, caption } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No image file uploaded" });
    }
    const newMessage = new Messages({
      senderId,
      receiverId,
      message: caption || "",
      imageUrl: req.file.path,
      timestamp: new Date(),
    });
    await newMessage.save();

    io.to(receiverId).emit("receive_message", {
      senderId,
      receiverId,
      message: caption || "",
      imageUrl: newMessage.imageUrl,
      timestamp: newMessage.timestamp,
    });

    res.status(201).json({ message: "Image sent", data: newMessage });
  } catch (error) {
    console.error("Error sending image:", error);
    res.status(500).json({ error: "Failed to send image" });
  }
});

// logout system
app.post("/api/logout", (req, res) => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
  });

  return res.status(200).json({ message: "Logged out successfully" });
});
// Start server
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
