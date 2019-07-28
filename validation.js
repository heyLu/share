function validateFileSize(maxFileSize, fileElement) {
	for (file of fileElement.files) {
		if (file.size > maxFileSize) {
			fileElement.setCustomValidity("The file is too big");
		} else {
			fileElement.setCustomValidity("");
		}
	}
}
