//AUTHENTICATION MIDDLEWARE
module.exports.isAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    // res.redirect("/login");
    res.status(401).json({ msg: "Unauthorized Entry! Please login" });
  }
};

module.exports.isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.admin) {
        return next();
      } else {
        // res.redirect("/login");
        res.status(401).json({ msg: "Unauthorized Entry! You are not an admin" });
      }
};
