const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sanitizeHtml = require('sanitize-html');
const xss = require('xss-clean');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'default-secret-change-me'));

app.use(
    cors({
        origin: process.env.ALLOWED_ORIGINS
            ? process.env.ALLOWED_ORIGINS.split(',')
            : '*',
        methods: ['POST', 'GET', 'OPTIONS'],
        allowedHeaders: [
            'Content-Type',
            'X-Requested-With',
            'X-Request-ID',
            'Authorization',
            'CSRF-Token',
            'csrf-token',
        ],
        credentials: true,
        maxAge: 86400,
    })
);

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                baseUri: ["'self'"],
                fontSrc: ["'self'", 'https:', 'data:'],
                frameAncestors: ["'self'"],
                imgSrc: ["'self'", 'data:'],
                objectSrc: ["'none'"],
                scriptSrc: ["'self'"],
                scriptSrcAttr: ["'none'"],
                styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
                upgradeInsecureRequests: [],
            },
        },
        crossOriginEmbedderPolicy: false,
    })
);

app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.RATE_LIMIT_MAX || 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        status: 429,
        success: false,
        message: 'Too many requests from this IP, please try again later.',
    },
});

app.use('/api/contact', apiLimiter);

const csrfProtection = csrf({
    cookie: {
        httpOnly: process.env.NODE_ENV === 'production',
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    },
});

app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {},
        disallowedTagsMode: 'discard',
    });
};

const validateContactForm = [
    body('name')
        .trim()
        .notEmpty()
        .withMessage('Name is required')
        .isLength({ max: 100 })
        .withMessage('Name must be less than 100 characters')
        .matches(/^[a-zA-Z0-9\s.,'-]+$/)
        .withMessage('Name contains invalid characters')
        .customSanitizer(sanitizeInput),

    body('email')
        .trim()
        .notEmpty()
        .withMessage('Email is required')
        .isEmail()
        .withMessage('Must be a valid email address')
        .isLength({ max: 100 })
        .withMessage('Email must be less than 100 characters')
        .normalizeEmail(),

    body('subject')
        .trim()
        .notEmpty()
        .withMessage('Subject is required')
        .isLength({ max: 200 })
        .withMessage('Subject must be less than 200 characters')
        .matches(/^[a-zA-Z0-9\s.,?!'-]+$/)
        .withMessage('Subject contains invalid characters')
        .customSanitizer(sanitizeInput),

    body('message')
        .trim()
        .notEmpty()
        .withMessage('Message is required')
        .isLength({ max: 5000 })
        .withMessage('Message must be less than 5000 characters')
        .customSanitizer(sanitizeInput),

    body('to')
        .trim()
        .isEmail()
        .withMessage('Recipient email must be valid')
        .custom((value) => {
            const allowedRecipients = process.env.ALLOWED_RECIPIENTS
                ? process.env.ALLOWED_RECIPIENTS.split(',')
                : ['saiharikiran.vasu@gmail.com'];

            if (!allowedRecipients.includes(value)) {
                throw new Error('Invalid recipient');
            }
            return true;
        }),

    body('requestId').trim().notEmpty().withMessage('Request ID is required'),

    body('timestamp')
        .isNumeric()
        .withMessage('Timestamp must be a number')
        .custom((value) => {
            const now = Date.now();
            const fiveMinutesAgo = now - 5 * 60 * 1000;
            if (value < fiveMinutesAgo || value > now + 60000) {
                throw new Error('Request expired');
            }
            return true;
        }),
];

app.post(
    '/api/contact',
    csrfProtection,
    validateContactForm,
    async (req, res) => {
        try {
            if (!req.get('X-Requested-With')) {
                return res.status(403).json({
                    success: false,
                    message: 'Forbidden',
                });
            }

            if (req.body.requestId !== req.get('X-Request-ID')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid request',
                });
            }

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    errors: errors.array(),
                });
            }

            const { name, email, subject, message, to, requestId } = req.body;

            const transporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: process.env.SMTP_PORT,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASSWORD,
                },
                tls: {
                    rejectUnauthorized: process.env.NODE_ENV === 'production',
                },
            });

            const mailOptions = {
                from: `"Contact Form" <${process.env.SMTP_FROM_EMAIL}>`,
                to: to,
                replyTo: email,
                subject: `Contact Form: ${subject}`,
                text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}\n\n---\nSubmission ID: ${requestId}\nTimestamp: ${new Date().toISOString()}`,
                html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #3182ce;">New Contact Form Submission</h2>
              <p><strong>From:</strong> ${name} (${email})</p>
              <p><strong>Subject:</strong> ${subject}</p>
              <div style="margin-top: 20px; padding: 15px; background-color: #f7fafc; border-radius: 5px;">
                <p style="margin-top: 0;"><strong>Message:</strong></p>
                <p style="white-space: pre-line;">${message}</p>
              </div>
              <div style="margin-top: 30px; padding: 10px; background-color: #f0f0f0; border-radius: 5px; font-size: 12px;">
                <p style="margin: 0;"><strong>Submission Details:</strong></p>
                <p style="margin: 5px 0;">ID: ${requestId}</p>
                <p style="margin: 5px 0;">Time: ${new Date().toISOString()}</p>
                <p style="margin: 5px 0;">This email was sent from your website contact form.</p>
              </div>
            </div>
          `,
            };

            await transporter.sendMail(mailOptions);

            return res.status(200).json({
                success: true,
                message: 'Your message has been sent successfully!',
                requestId: requestId,
            });
        } catch (error) {
            return res.status(500).json({
                success: false,
                message:
                    'An error occurred while sending your message. Please try again later.',
            });
        }
    }
);

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: Date.now() });
});

app.use((req, res) => {
    res.status(404).json({ message: 'Not Found' });
});

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({
            success: false,
            message: 'Invalid or missing CSRF token',
        });
    }

    res.status(500).json({
        success: false,
        message: 'Something went wrong on the server.',
    });
});

module.exports = app;
