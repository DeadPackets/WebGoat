function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
    // credentials must never be shipped to, or sent from, the browser in the clear
    xhttp['send']();
}
