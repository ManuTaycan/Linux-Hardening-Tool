## Summary

<!-- What changes? -->

## Motivation and security impact

<!-- Risk, security benefit, and possible side effects. -->

## Changed components

<!-- Script, documentation, CI, installer, or templates. -->

## Test evidence

<!-- Commands and results; never include secrets in logs. -->

## Rollback

<!-- How is the prior state restored? -->

## Lynis impact

<!-- Expected or measured effect, without score gaming. -->

## Checklist

- [ ] No secrets or unredacted production logs included
- [ ] SSH port policy preserved or explicitly reviewed
- [ ] No GRUB password added
- [ ] Checksum updated and verified when harden.sh changed
- [ ] Test and rollback paths documented
