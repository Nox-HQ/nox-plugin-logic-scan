const express = require('express');
const app = express();
app.use(express.json());

// IDOR: no ownership check
app.get("/api/users/:id", (req, res) => {
    const user = db.findUser(req.params.id);
    res.json(user);
});

// Missing auth on admin route
app.delete("/api/admin/users/:id", (req, res) => {
    db.deleteUser(req.params.id);
    res.json({ status: "deleted" });
});

// Mass assignment: binds req.body directly
app.put("/api/users/:id", (req, res) => {
    const updated = db.updateUser(req.params.id, req.body);
    res.json(updated);
});

app.listen(3000);
