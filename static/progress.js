function start_long_task() {
        div = $('<div class="progress"><div class="progress-bar" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div></div');
        $('#progress').append(div);

        $.ajax({
                type: 'POST',
                url: '/longtask',
                success: function(data, status, request) {
                        status_url = request.getResponseHeader('Location');
                        update_progress(status_url, nanobar, div[0]);
                },
                error: function() {
                        alert('Unexpected error');
                }
        });
}

function update_progress(status_url, nanobar, status_div) {
        // send GET request to status URL
        $.getJSON(status_url, function(data) {
                percent = parseInt(data['current'] * 100 / data['total']);
                if (data['state'] != 'PENDING' && data['state'] != 'PROGRESS') {
                        if ('result' in data) {
                                document.getElementById('progressBar').style.width=pe                      
                        }
                        else {
                                
                        }
                }
                else {
                        setTimeout(function() {
                                update_progress(status_url, nanobar, status_div);
                        }, 2000);
                }
        });
}

