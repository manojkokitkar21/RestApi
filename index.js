const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/assignment', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    unique: true,
  },
  password: String,
});

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
  title: String,
  body: String,
  image: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
});

const Post = mongoose.model('Post', postSchema);

// Registration API
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(200).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while registering the user' });
  }
});

// Login API
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id }, 'secret-key');
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while logging in' });
  }
});

// Middleware for authentication and authorization
const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, 'secret-key');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// CRUD routes for posts
app.get('/posts', authenticateUser, async (req, res) => {
  try {
    const posts = await Post.find().populate('user', 'name');
    res.status(200).json({ posts });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while fetching posts' });
  }
});

app.post('/posts', authenticateUser, async (req, res) => {
  const { title, body, image } = req.body;

  try {
    const post = new Post({
      title,
      body,
      image,
      user: req.userId,
    });

    await post.save();
    res.status(200).json({ post });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while creating the post' });
  }
});

app.put('/posts/:postId', authenticateUser, async (req, res) => {
  const { postId } = req.params;
  const { title, body, image } = req.body;

  try {
    const post = await Post.findOne({ _id: postId });

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (post.user.toString() !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    post.title = title;
    post.body = body;
    post.image = image;

    await post.save();
    res.status(200).json({ post });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while updating the post' });
  }
});

app.delete('/posts/:postId', authenticateUser, async (req, res) => {
  const { postId } = req.params;

  try {
    const post = await Post.findOne({ _id: postId });

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    if (post.user.toString() !== req.userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    await post.remove();
    res.status(200).json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while deleting the post' });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
