//
// FrAUI.js (macOS)
// Fried Apple Framework
//
// Created by Alexander Hude on 31/12/15.
// Copyright (c) 2015 FriedApple. All rights reserved.
//

function ShowAlert(title, message)
{
    const nsAlert = NSAlert.alloc().init();
    nsAlert.setMessageText_(NSString.alloc().initWithString_(title));
    nsAlert.setInformativeText_(NSString.alloc().initWithString_(message));
    nsAlert.runModal();
}

