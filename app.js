const fs = require('fs');
const express = require("express");
const session = require('express-session');
const passport = require('passport');
const saml = require('passport-saml');
const cors = require('cors');
const path = require('path');

const app = express();

passport.serializeUser((user, done) => done(null, user));

passport.deserializeUser((user, done) => done(null, user));

const samlStrategy = new saml.Strategy({
  callbackUrl: "http://localhost:4006/api/auth/login/callback",
  entryPoint: "https://wayf.ucol.mx/saml2/idp/SSOService.php",
  logoutUrl: 'https://wayf.ucol.mx/saml2/idp/SingleLogoutService.php',
  logoutCallbackUrl: 'http://localhost:4006/logout/callback',
  issuer: "http://localhost/20166932",
  decryptionPvk: fs.readFileSync(__dirname + '/cert/key.pem', 'utf8'),
  cert: fs.readFileSync(__dirname + '/cert/idp.crt', 'utf8'),
  acceptedClockSkewMs: 30000
}, (profile, done)=>{ const user= Object.assign({},profile); return done(null, profile)} );

app.use(session({
  secret: "thisismysecrctekeyfhrgfgrfrty84fwir767",
  saveUninitialized: true,
  resave: true
  
}));

app.use("/assets", express.static(__dirname + "/public"));

passport.use(samlStrategy);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cors());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', passport.authenticate('saml', { failureRedirect: '/login/fail', failureFlash: true}), (req, res) => res.redirect('/'));

app.post('/api/auth/login/callback', passport.authenticate('saml', { 
  failureRedirect: '/login/fail',
  failureFlash: true
}), (req, res) => {
  res.redirect('/inicio')
});

// Agrega esta ruta después de la configuración de passport
app.get('/inicio', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  const uNombre = req.user?.uNombre;
  const uCorreo = req.user?.uCorreo;
  const uDependencia = req.user?.uDependencia;
  const uCuenta = req.user?.uCuenta;
  const uTipo = req.user?.uTipo;

  res.render('inicio', { nombre: uNombre, noCuenta: uCuenta, correo: uCorreo, dependencia: uDependencia, tipo: uTipo });
});

  app.get('/logout', (req, res)=> {
       
    if (!req.user) res.redirect('/');
    
    samlStrategy.logout(req, (err, request) =>{
      return res.redirect(request)
    });
   });

   app.post('/api/auth/logout/callback', (req, res) =>{
    req.logout();
    res.redirect('/');
  });

app.get('/login/fail', (req, res) => res.status(401).send('Login failed'));

app.get('/Metadata', (req, res) => {
    res.type('application/xml');
    res.status(200).send(samlStrategy.generateServiceProviderMetadata(fs.readFileSync(__dirname + '/cert/cert.pem', 'utf8')));
  }
);

//general error handler
app.use((err, req, res, next) => {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

const server = app.listen(4006, () => console.log('Listening on port %d', server.address().port));