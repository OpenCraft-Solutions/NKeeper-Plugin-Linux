import { adoptStyles, definePlugin } from '@nkeeper/sdk'
import { FilesView } from './FilesView'
import { JournalView } from './JournalView'
import { SelinuxView } from './SelinuxView'
import { toolStyles } from './ToolFrame'

const plugin = definePlugin({
  id: 'linux',
  activate() {
    // Constructable stylesheets: the shell's policy blocks <style> elements (docs/architecture.md §7.14).
    adoptStyles(toolStyles)
  },
  sessionViews: { 'linux-files': FilesView, 'linux-journal': JournalView, 'linux-selinux': SelinuxView },
})

export default plugin
