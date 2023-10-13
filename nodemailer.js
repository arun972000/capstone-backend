import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'arunpandian972000@gmail.com',
    pass: 'croxlsqtgimurnjf'
  }
});

export const mailOptions = {
  from: 'arunpandian972000@gmail.com',
  to: 'myfriend@yahoo.com',
  subject: 'Password reset Link',
  text: 'That was easy!'
};

