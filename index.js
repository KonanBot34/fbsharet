const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();

app.use(express.json());
app.use(express.static(__dirname));
app.use(session({secret:'secret',resave:false,saveUninitialized:false}));

const users = []; // demo in-memory

function genKey(){return "VKEY-"+Math.random().toString(16).slice(2,8).toUpperCase()+"-"+Math.random().toString(16).slice(2,6).toUpperCase()}

app.post('/api/register', async (req,res)=>{
  const {u,d,e,a,p,p2}=req.body;
  if(!u||!e||p!==p2) return res.json({msg:"Invalid"});
  if(users.find(x=>x.u===u||x.e===e)) return res.json({msg:"Exists"});
  const hash=await bcrypt.hash(p,10);
  const key=genKey();
  users.push({u,d,e,a,hash,status:'PENDING',key});
  res.json({msg:"Pending approval. Send key to admin.", key});
});

app.post('/api/login', async (req,res)=>{
  const {u,p}=req.body;
  const user=users.find(x=>x.u===u||x.e===u);
  if(!user) return res.json({msg:"Not found"});
  const ok=await bcrypt.compare(p,user.hash);
  if(!ok) return res.json({msg:"Wrong password"});
  if(user.status!=='APPROVED') return res.json({msg:"Status: "+user.status});
  req.session.u=user.u;
  res.json({ok:true,msg:"Login success"});
});

// ---- ADMIN DEMO ENDPOINTS ----
app.get('/admin/pending',(req,res)=>res.json(users.filter(u=>u.status==='PENDING')));
app.post('/admin/approve',(req,res)=>{
  const u=users.find(x=>x.key===req.body.key);
  if(!u) return res.json({msg:"Key not found"});
  u.status='APPROVED'; u.key=null;
  res.json({msg:"Approved"});
});

app.listen(3000,()=>console.log("Running http://localhost:3000"));
