export const generalResponse = ({ response, message, status, data = null }) =>
  response.status(status).json({
    status,
    message,
    data,
  });
