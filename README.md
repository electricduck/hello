<p align="center">
  <a href="https://github.com/electricduck/hello">
    <img src=".github/logo.png" width=80 height=80>
  </a>

  <h3 align="center">Hello</h3>

  <p align="center">
    A colourful welcome mat for PowerShell
  </p>
  
  <p align="center">
  <img src="https://i.imgur.com/vygwE2q.png">
  </p>
</p>

## Using Hello

### Installing

```
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/electricduck/hello/develop/Install-Hello.ps1'))
```

Using PowerShell 5.1 **or** [Powershell Core 6.0+](https://github.com/powershell/powershell), issue the above command, and then restart your shell. Easy, right?

### Updating

Updating Hello to the latest release can be done by issuing the below command. This will automatically download the latest stable release and install it; restart your shell to use.

```
~ ➜ Update-Hello
```

Updating Hello to the latest **development release** can be done by setting the `-Dev` parameter to `$true`. However, if something breaks and Hello no longer works, there is no way to revert this: you will need to destroy `hello.ps1` and install a fresh copy.

### Configuring

Basic customization is possible by setting environment variables in `$PROFILE`.

```
~ ➜ notepad $PROFILE # or another editor besides notepad
```

This is your PowerShell profile that is read on startup. If you've never touched this file before, you'll find just the statement telling PowerShell to "source" Hello.

```
. /home/you/.config/powershell/hello.ps1
```

Configuration variables **must** be added above the above line, and must be preceeded by `$env:HELLO_`. Other PowerShell statements can also be added here.

```
$env:HELLO_Caret = "👉"      # Change Hello's prompt from ➜ to a 👉
$env:HELLO_LogoColor = "Red" # Change Hello's logo from cyan to red

# Some other stuff
Set-Alias -Name cl -Value Clear-Host -Option AllScope # Create an alias for Clear-Host as "cl"

. /home/you/.config/powershell/hello.ps1
```

To test, configuration variables can also be temporarily set via the shell.

```
~ ➜ $env:HELLO_Caret = "👉" # Temporarily set an environment variable
~ ➜ pwsh                    # Spawn a child process (use 'powershell' for 5.1)
```

#### Possible variables

| **Variable** | **Type** | **Description** | **Default** |
| ------------ | -------- | --------------- | ----------- |
| **AllowUnsupported** | Bool* | _Allow installing/updating on unsupported PowerShell versions_ | `$false` |
| **Caret** | String | _Prompt character_ | `"➜"` |
| **LogoColor** | String | _Color of the ASCII PowerShell logo_ | `"Cyan"` |
| **WelcomeHighColor** | String | _High color of welcome messages (i.e. "PowerShell")_ | `"White"` |
| **WelcomeLowColor** | String | _Low color of welcome messages (i.e. "7.0.1")_ | `"Gray"` |

###### * In PowerShell, bools are expressed as `$true` or `$false`
