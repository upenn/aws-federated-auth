"""Shell completion add-on scripts for `export AWS_PROFILE` command."""
import os
import logging
import subprocess

logger = logging.getLogger(__name__)

class ShellCompletion:
    """Shell completion for AWS profile export command."""

    def __init__(
        self,
        exceptiontrace=False
    ):
        """Initialize the ShellCompletion instance."""
        self.exceptiontrace = exceptiontrace

    ########## Shell completion scripts ##########
    _omz_completion_script = """#compdef export
# `export AWS_PROFILE="` completion script for aws-federated-auth

_aws_profile_export() {
  local cur curval profiles matches

  # grab the word under the cursor
  cur=${words[CURRENT]}
  # only do our thing if they're completing AWS_PROFILE="
  if [[ $cur == AWS_PROFILE\=\"* ]]; then
    compstate[insert]="automenu"
    # strip off the whole "AWS_PROFILE=" prefix
    curval=${cur#AWS_PROFILE=\"}

    compset -P 'AWS_PROFILE="'
    # pull all profiles from $awsconfigfile
    # filter for the current value anywhere in the profile name
    profiles=(${(f)"$(grep "^\[.*$curval" $awsconfigfile 2>/dev/null \
                   | sed -e 's/^\[\(.*\)\]$/\\1/')"})
    
    compadd -Q -P AWS_PROFILE=\" -U -S '"' -- ${profiles[@]}
    return
  fi

  # fallback to the standard export/typeset completion
  _typeset "$@"
}
"""
    _bash_completion_script = r"""# `export AWS_PROFILE=` completion script for aws-federated-auth

_aws_profile_complete() {
    local cur profiles prefix
    cur="${COMP_WORDS[COMP_CWORD]}"
    prefix="AWS_PROFILE="

    if [[ ${#COMP_WORDS[@]} -eq 2 ]]; then
        # Assume = is not broken into separate word
        # Only trigger completion if the command starts with `export AWS_PROFILE=`
        if [[ ${COMP_WORDS[0]} == "export" && ${COMP_WORDS[1]} == "AWS_PROFILE="* ]]; then
            # Extract profile names from $awsconfigfile
            profiles=$(grep '^\[' $awsconfigfile 2>/dev/null | sed 's/^\[\(.*\)\]$/\1/')

            COMPREPLY=( $(compgen -W "${profiles}" -- "${cur#${prefix}}") )
        fi
    elif [[ ${#COMP_WORDS[@]} -gt 2 ]]; then
        # Assume = is broken into separate word
        # Only trigger completion if the command starts with `export AWS_PROFILE=`
        if [[ ${COMP_WORDS[0]} == "export" && ${COMP_WORDS[1]} == "AWS_PROFILE" && ${COMP_WORDS[2]} == "="* ]]; then
            # Extract profile names from $awsconfigfile
            profiles=$(grep '^\[' $awsconfigfile 2>/dev/null | sed 's/^\[\(.*\)\]$/\1/')
            
            if [[ ${cur} == "=" ]]; then
                cur=""
            fi

            COMPREPLY=( $(compgen -W "${profiles}" -- "${cur}") )
        fi
    fi
}

# Register the completion for the `export` command
complete -F _aws_profile_complete export

# `aws-federated-auth` completion script

_aws_federated_auth_complete() {
    local cur
    cur="${COMP_WORDS[COMP_CWORD]}"
    
    all_options=(
        "--account"
        "--accountalias"
        "--rolename"
        "--profilename"
        "--list"
        "--assertionconsumer"
        "--idpentryurl"
        "--duofactor"
        "--awsconfigfile"
        "--sslverification"
        "--outputformat"
        "--region"
        "--cookiejar"
        "--logging"
        "--exceptiontrace"
        "--timer"
        "--max-duration-limit"
        "--skip-max-duration-check"
        "--storepass"
        "--user"
        "--sort_display"
        "--split_display"
        "--install-completion"
        "--completion-location"
    )
    if [[ ${cur} == -* || ( -z ${cur} && $3 == aws-federated-auth ) ]]; then
        COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
        return
    fi

    # Find the option being completed
    # go backwards in COMP_WORDS to find the last --option
    option=""
    option_args=()
    temp_args=()
    account_numbers=()
    account_aliases=()
    role_name=""
    awsconfigfile="$HOME/.aws/credentials"
    for ((i=${#COMP_WORDS[@]}-1; i>=0; i--)); do
        if [[ -z ${option} ]]; then
            if [[ ${COMP_WORDS[i]} == --* ]]; then
                option=${COMP_WORDS[i]}
            elif [[ -n ${COMP_WORDS[i]} ]]; then
                option_args+=("${COMP_WORDS[i]}")
            fi
        else
            case ${COMP_WORDS[i]} in
                --account)
                    account_numbers=("${temp_args[@]}")
                    temp_args=()
                    ;;
                --accountalias)
                    account_aliases=("${temp_args[@]}")
                    temp_args=()
                    ;;
                --rolename)
                    if [[ ${#temp_args[@]} -eq 1 ]]; then
                        role_name="${temp_args[0]}"
                    fi
                    temp_args=()
                    ;;
                --awsconfigfile)
                    if [[ ${#temp_args[@]} -eq 1 ]]; then
                        awsconfigfile="${temp_args[0]/#\~/$HOME}"
                    fi
                    temp_args=()
                    ;;
                *)
                    temp_args+=("${COMP_WORDS[i]}")
                    ;;
            esac
        fi
    done

    case ${option} in
        --list|--storepass)
            # No completions for these options
            COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
            return
            ;;
        --duofactor)
            if [[ ${#option_args[@]} -gt 0 && -z ${cur} ]]; then
                COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
                return
            fi
            matches=("auto" "push" "phone" "passcode")
            ;;
        --logging)
            if [[ ${#option_args[@]} -gt 0 && -z ${cur} ]]; then
                COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
                return
            fi
            matches=("critical" "warn" "error" "info" "debug")
            ;;
        --sort_display|--split_display)
            if [[ ${#option_args[@]} -gt 3 && -z ${cur} ]]; then # Max options reached
                COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
                return
            fi
            matches=("account_number" "max_duration" "profile_name" "role_name")
            ;;
        --account)
            if [[ -f $awsconfigfile ]]; then
                mapfile -t matches < <(
                    awk -v target="$role_name" -v als="$(printf '%s\t' "${account_aliases[@]}")" '
                        BEGIN {
                            n_als = split(als, alist, "\t")
                            for (i = 1; i <= n_als; i++) {
                                if (alist[i] != "") {
                                    aset[alist[i]] = 1
                                }
                            }
                        }
                        /^\[/               { account=""; alias=""; role="" }   # new section → reset
                        /^account_number/   { account=$3 }
                        /^account_alias/    { alias=$3 }
                        /^role_name/        { role=$3 }
                        account && role {
                            # If no target specified, accept all roles
                            if ((target == "" || role == target) && !(alias in aset)) {
                                print account
                            }
                            account=""; alias=""; role=""                       # reset after print
                        }
                    ' "$awsconfigfile" | sort -u
                )
            fi
            ;;
        --accountalias)
            if [[ -f $awsconfigfile ]]; then
                mapfile -t matches < <(
                    awk -v target="$role_name" -v nums="$(printf '%s\t' "${account_numbers[@]}")" '
                        BEGIN {
                            n_nums = split(nums, nlist, "\t")
                            for (i = 1; i <= n_nums; i++) {
                                if (nlist[i] != "") {
                                    nset[nlist[i]] = 1
                                }
                            }
                        }
                        /^\[/              { account=""; alias=""; role="" }   # new section → reset
                        /^account_number/  { account=$3 }
                        /^account_alias/   { alias=$3 }
                        /^role_name/       { role=$3 }
                        alias && role {
                            # If no target specified, accept all roles
                            if ((target == "" || role == target) && !(account in nset)) {
                                print alias
                            }
                            account=""; alias=""; role=""                      # reset after print
                        }
                    ' "$awsconfigfile" | sort -u
                )
            fi
            ;;
        --rolename)
            if [[ -f $awsconfigfile ]]; then
                # Join selected accounts into tab-separated strings for awk
                nums_joined=""
                if (( ${#account_numbers[@]} )); then
                    nums_joined="$(printf '%s\t' "${account_numbers[@]}")"
                    nums_joined="${nums_joined%$'\t'}"
                fi

                aliases_joined=""
                if (( ${#account_aliases[@]} )); then
                    aliases_joined="$(printf '%s\t' "${account_aliases[@]}")"
                    aliases_joined="${aliases_joined%$'\t'}"
                fi

                # Collect role names filtered by the selected accounts (if any)
                mapfile -t matches < <(
                    awk -v nums="$nums_joined" -v als="$aliases_joined" '
                        BEGIN {
                            n_ok = split(nums, nlist, "\t");
                            a_ok = split(als,  alist, "\t");
                            for (i=1;i<=n_ok;i++) if (nlist[i]!="") nset[nlist[i]] = 1;
                            for (i=1;i<=a_ok;i++) if (alist[i]!="") aset[alist[i]] = 1;
                        }
                        /^\[/               { acc=""; alias=""; role="" }    # new section
                        /^account_number/   { acc=$3 }
                        /^account_alias/    { alias=$3 }
                        /^role_name/        { role=$3 }
                        role {
                            # If no filters provided, accept all roles.
                            # Otherwise require that this section matches either selected account_number or account_alias.
                            if ((n_ok==0 && a_ok==0) || (n_ok>0 && (acc in nset)) || (a_ok>0 && (alias in aset))) {
                                print role
                            }
                            role=""  # avoid double print within same section
                        }
                    ' "$awsconfigfile" | sort -u
                )
            fi
            ;;
        --profilename)
            if [[ -f $awsconfigfile ]]; then
                # Collect all profile names (section headers without [ ])
                mapfile -t matches < <(
                    grep '^\[' "$awsconfigfile" \
                    | sed 's/^\[\(.*\)\]$/\1/' \
                    | sort -u
                )
            fi
            ;;
        *)
            COMPREPLY=( $(compgen -W "${all_options[*]}" -- "$cur") )
            return
            ;;
    esac

    filtered=()
    for match in "${matches[@]}"; do 
        skip=false
        for arg in "${option_args[@]}"; do
            if [[ "$match" == "$arg" ]]; then
                skip=true
                break
            fi
        done
        if ! $skip; then
            filtered+=("$match")
        fi
    done
    COMPREPLY=($(compgen -W "${filtered[*]}" -- "${cur}"))

}

# Register the completion for the `aws-federated-auth` command
complete -F _aws_federated_auth_complete aws-federated-auth
"""

    ########## Class methods ##########
    def install_completion(
        self,
        shell_type: str,
        completion_location: str = None
    ):
        """Install the shell completion script for the specified shell type."""
        if shell_type not in ('bash', 'omz'):
            raise ValueError("Unsupported shell type. Use 'bash' or 'omz'.")
        
        if shell_type == 'bash':
            self._install_bash_completion(completion_location)
        elif shell_type == 'omz':
            self._install_omz_completion(completion_location)
        return

    def _install_bash_completion(self, completion_location: str = None):
        """Install the bash completion script."""
        if not completion_location:
            completion_location = '~/._aws_profile_complete.sh'
        # Confirm that the location exists
        os.makedirs(os.path.dirname(os.path.expanduser(completion_location)), exist_ok=True)
        
        # Check if file exists, create if not
        if not os.path.exists(os.path.expanduser(completion_location)):
            with open(os.path.expanduser(completion_location), 'w') as f:
                f.write(self._bash_completion_script)
            logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
            print(f"Bash completion script installed at {completion_location}")
        else:
            # Check if script is already present
            with open(os.path.expanduser(completion_location), 'r') as f:
                content = f.read()
            if '_aws_profile_complete()' in content:
                logger.error(f"Bash completion script _aws_profile_complete() already exists in {completion_location}.\n"
                              "No changes made.\n"
                              "If you want to update it, please remove the existing script first.",
                              exc_info=self.exceptiontrace)
                return
            else: # Add script to end of existing file
                with open(os.path.expanduser(completion_location), 'a') as f:
                    f.write('\n' + self._bash_completion_script)
                logger.debug(f"Bash completion script:\n{self._bash_completion_script}")
                print(f"Bash completion script appended to {completion_location}")
                
        # Source the completion script in .bashrc
        # Ask for user confirmation to add sourcing line
        sourcetext = f'source {os.path.expanduser(completion_location)}\n'
        if not sourcetext in open(os.path.expanduser('~/.bashrc'), 'r').read():
            add_source = input(f'To automatically load the completion script on terminal start, `source {completion_location}` needs to be added to your .bashrc file.\n'
                               'Do you want to add this line? (y/n): ').strip().lower()
            if add_source == 'y':
                if not os.path.exists(os.path.expanduser('~/.bashrc')):
                    with open(os.path.expanduser('~/.bashrc'), 'w') as f:
                        f.write(sourcetext)
                else:
                    with open(os.path.expanduser('~/.bashrc'), 'a') as f:
                        f.write(f'\n{sourcetext}')
                print("Source line added to your .bashrc file.")
            else:
                print("You can manually add the following line to your .bashrc file to enable completion on terminal start:")
                print(f'source {os.path.expanduser(completion_location)}')

            print("Please restart your terminal to apply changes.")
        return
    
    def _install_omz_completion(self, completion_location: str = None):
        """Install the oh-my-zsh completion script."""
        if not completion_location:
            completion_location = '~/.oh-my-zsh/custom/completions/_aws_profile_export'
        # Confirm that the location ends in `_aws_profile_export`
        if not completion_location.endswith('_aws_profile_export'):
            logger.error(f"Completion location must end with '_aws_profile_export'.")
            return
         
        # Check if file exists, create if not
        script_added = False
        if not os.path.exists(os.path.expanduser(completion_location)):
            # Confirm that location exists
            os.makedirs(os.path.dirname(os.path.expanduser(completion_location)), exist_ok=True)
            # Write the completion script to the file
            with open(os.path.expanduser(completion_location), 'w') as f:
                f.write(self._omz_completion_script)
            logger.debug(f"oh-my-zsh completion script:\n{self._omz_completion_script}")
            print(f"oh-my-zsh completion script installed at {completion_location}")
            script_added = True
        else:
            logger.error(f"oh-my-zsh completion script _aws_profile_export() already exists in {completion_location}.\n"
                          "No changes made.\n"
                          "If you want to update it, please remove the existing script first.")
            
        # Confirm that location is in $fpath
        fpath = self._get_zsh_fpath()
        if os.path.dirname(os.path.expanduser(completion_location)) not in fpath:
            logger.debug(f"Directory {os.path.dirname(os.path.expanduser(completion_location))} is not in user's $fpath.")
            add_fpath = input(f'The directory {os.path.dirname(os.path.expanduser(completion_location))} is not in your $fpath.\n'
                              'This location needs to be in your $fpath for the completion script to load automatically.\n'
                              'Do you want to add the location to your $fpath? (y/n): ').strip().lower()
            if add_fpath == 'y':
                with open(os.path.expanduser('~/.zshrc'), 'r') as f:
                    previous_content = f.read()
                with open(os.path.expanduser('~/.zshrc'), 'w') as f:
                    f.write(f'# added by aws-federated-auth --install-completion\nfpath=({os.path.dirname(os.path.expanduser(completion_location))} $fpath)\n\n')
                    f.write(previous_content)
                print("Directory added to your $fpath.")
                script_added = True
                logger.debug(f"Added fpath line to ~/.zshrc: fpath=({os.path.dirname(os.path.expanduser(completion_location))} $fpath)")
            else:
                print("You can manually add the following line to your .zshrc file before oh-my-zsh is loaded to enable completion on terminal start:")
                print(f'fpath=({os.path.dirname(os.path.expanduser(completion_location))} $fpath)')
                logger.debug(f"User chose not to add fpath line to ~/.zshrc: fpath=({os.path.dirname(os.path.expanduser(completion_location))} $fpath)")
        else:
            logger.debug(f"Directory {os.path.dirname(os.path.expanduser(completion_location))} is already in user's $fpath.")

        # If script added, prompt to source .zshrc
        if script_added:
            print("Please restart your terminal or run `omz reload` to apply changes.")

        return
    
    def _get_zsh_fpath(self):
        """Get the current zsh fpath."""
        try:
            result = subprocess.run(
                ['zsh', '-i', '-c', 'print -l $fpath'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting zsh fpath.", exc_info=self.exceptiontrace)
            return []
