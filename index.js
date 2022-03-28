require('dotenv').config();
const bcrypt = require('bcrypt');
const express = require('express');
const morgan = require('morgan');
const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const validator = require('email-validator');

const app = express();

const handler = (res, code, message) =>
  res.status(code).json({ success: false, message });

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    dateCreated: { type: Date, default: new Date() },
    lastLogin: { type: Date, default: new Date() }
  }).plugin(uniqueValidator)
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(morgan('[:date[clf]] :method :url   :status  :response-time ms'));

app.post('/register', async (req, res) => {
  if (!req.body.name) return handler(res, 401, 'Provide valid name');
  else if (!req.body.email || !validator.validate(req.body.email))
    return handler(res, 401, 'Provide valid email');
  else if (!req.body.phone) return handler(res, 401, 'Provide valid phone');
  else if (!req.body.password)
    return handler(res, 401, 'Provide valid password');

  try {
    const { name, email, password, phone } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ name, email, password: hashedPassword, phone }).save();
    return res.status(200).json({
      success: true,
      message: 'User successfully created'
    });
  } catch (error) {
    if (error.errors.email) {
      const e = error.errors.email;
      if (e.kind === 'unique' && e.path === 'email') {
        return handler(res, 401, `User with email: ${e.value} exists already.`);
      }
    } else {
      console.error(error);
      return handler(res, 500, `Server Error: ${error.message}`);
    }
  }
});

app.use('**', (_, res) => res.status(404).send('Not Found'));

module.exports = app.listen(process.env.PORT, async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Successfully connected to MongoDB!');
    console.log('Server listening on port ' + process.env.PORT);
  } catch (error) {
    console.log('Unable to connect to MongoDB!');
    console.error(error);
  }
});
