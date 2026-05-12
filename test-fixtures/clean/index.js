function capitalize(str) {
  return str.replace(/\b\w/g, c => c.toUpperCase());
}

function slugify(str) {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

module.exports = { capitalize, slugify };
