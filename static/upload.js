$(document).ready(function() {
	$('form').on('submit', function(event) {
		event.preventDefault();
		var formData = new FormData($('form')[0]);

		$.ajax({
			type: 'POST',
			url: '/upload',
			data: formData,
			contentType: false,
			processData: false,
			dataType: 'json'
			beforeSend: function() {
				alert('File uploading');
			}
	}};

