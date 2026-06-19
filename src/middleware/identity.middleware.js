// Extrait l'identité de l'utilisateur depuis les headers injectés par la gateway
// Ces headers sont ajoutés après vérification du JWT côté gateway, pas ici
module.exports = (req, res, next) => {
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role'];
  const username = req.headers['x-user-username'];

  if (!userId) {
    return res.status(401).json({
      error: {
        code: 'MISSING_IDENTITY',
        message: 'Identité manquante.'
      }
    });
  }

  req.userId = userId;
  req.userRole = userRole;
  req.username = username;

  next();
};
