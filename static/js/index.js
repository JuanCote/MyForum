// Get a reference to our file input
    const fileInput = document.querySelector('input[name="file"]');

    // Create a new File object
    const myFile = new File(['Hello World!'], 'myFile.txt', {
        type: 'text/plain',
        lastModified: new Date(),
    });

    // Now let's create a DataTransfer to get a FileList
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(myFile);
    fileInput.files = dataTransfer.files;