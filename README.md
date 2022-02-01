# Callback-Registration
Register a callback from a Manually mapped kernel module

Typically, when manually mapping your driver, you want to refrain from creating a DriverObject as that can be easily detected. By doing this,
you are unable to register callbacks which can be a very useful feature when trying to IAT hook, or protect your process. By taking a look in IDA, you
will see that Windows checks the address of the callback function, and if it is outside of a valid module, they will prevent the Callback from being registered.
By Hooking a function in a valid module to jump to our callback, we can pass the address of the valid function to the callback registration function. This will 
allow our callback to succesfully register, and do whatever we want. This project changes the .text section of a valid module which is a big flag for anticheat, 
but it is a simple POC and with a little more effort can be made very usable for BE or EAC!
